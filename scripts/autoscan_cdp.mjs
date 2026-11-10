// Local browser lifecycle checks; Node's built-in WebSocket is the only CDP client.
import fs from 'node:fs';
const [profile, action, extensionId, testUrl, mv3Path] = process.argv.slice(2);
const [port, browserPath] = fs.readFileSync(profile + '/DevToolsActivePort', 'utf8').trim().split('\n');
async function connect(url) {
  const ws = new WebSocket(url);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = e => {
    const message = JSON.parse(e.data), entry = pending.get(message.id);
    if (entry) { clearTimeout(entry.timer); pending.delete(message.id); entry.resolve(message); }
  };
  return {ws, call(method, params = {}) {
    return new Promise((resolve, reject) => {
      const key = ++id;
      const timer = setTimeout(() => { pending.delete(key); reject(new Error(method + ' timed out')); }, 8000);
      pending.set(key, {resolve, timer}); ws.send(JSON.stringify({id: key, method, params}));
    });
  }};
}
const browser = await connect(`ws://127.0.0.1:${port}${browserPath.trim()}`);
if (action === 'close') {
  await browser.call('Browser.close'); browser.ws.close();
} else {
  if (mv3Path) {
    const loaded = await browser.call('Extensions.loadUnpacked', {path: mv3Path});
    if (loaded.error || !loaded.result?.id) throw new Error('MV3 control failed to load: ' + JSON.stringify(loaded));
  }
  const target = await (await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent('chrome://extensions/')}`, {method: 'PUT'})).json();
  const client = await connect(target.webSocketDebuggerUrl);
  async function evaluate(expression) {
    const response = await client.call('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true, userGesture: true});
    if (response.error || response.result?.exceptionDetails) throw new Error(JSON.stringify(response));
    return response.result?.result?.value;
  }
  const getInfo = () => evaluate('new Promise(resolve=>{if(!chrome.developerPrivate)return resolve([]);chrome.developerPrivate.getExtensionsInfo({includeDisabled:true,includeTerminated:true},resolve)})');
  let extension;
  for (let attempt = 0; attempt < 40; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 250));
    extension = (await getInfo())?.find(e => e.id === extensionId);
    if (extension) break;
  }
  const brief = e => e && ({id: e.id, name: e.name, state: e.state, location: e.location,
    isAffectedByMV2Deprecation: e.isAffectedByMV2Deprecation, disableReasons: e.disableReasons,
    manifestErrors: e.manifestErrors, runtimeErrors: e.runtimeErrors});
  const result = {before: brief(extension)};
  if (action === 'enable') {
    if (!extension || extension.location === 'UNPACKED') throw new Error('Expected a packed external extension: ' + JSON.stringify(brief(extension)));
    if (extension.isAffectedByMV2Deprecation || extension.disableReasons?.unsupportedManifestVersion) throw new Error('MV2 is still affected');
    const oldTargets = new Set((await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).map(t => t.id));
    for (const enabled of [false, true]) {
      const error = await evaluate(`new Promise(resolve=>chrome.management.setEnabled(${JSON.stringify(extensionId)},${enabled},()=>resolve(chrome.runtime.lastError?.message??null)))`);
      if (error) throw new Error(error + ': ' + JSON.stringify(brief(extension)));
      const info = (await getInfo()).find(e => e.id === extensionId);
      if (info.state !== (enabled ? 'ENABLED' : 'DISABLED')) throw new Error('Enable/disable did not take effect: ' + JSON.stringify(brief(info)));
    }
    result.after = brief((await getInfo()).find(e => e.id === extensionId));
    let ready = false;
    for (let attempt = 0; attempt < 40 && !ready; attempt++) {
      const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const target = targets.find(t => t.type === 'background_page' && t.url.startsWith(`chrome-extension://${extensionId}/`) && !oldTargets.has(t.id));
      if (target) {
        const background = await connect(target.webSocketDebuggerUrl);
        const response = await background.call('Runtime.evaluate', {expression: 'globalThis.mv2Ready === true', returnByValue: true});
        background.ws.close(); ready = response.result?.result?.value === true;
      }
      if (!ready) await new Promise(resolve => setTimeout(resolve, 250));
    }
    if (!ready) throw new Error('The enabled MV2 background page did not register its listener');
  } else if (action === 'offstore-blocked') {
    if (!extension || extension.state !== 'DISABLED' || !extension.disableReasons?.suspiciousInstall ||
        extension.isAffectedByMV2Deprecation || extension.disableReasons?.unsupportedManifestVersion)
      throw new Error('Expected only the off-store verification block: ' + JSON.stringify(brief(extension)));
    result.enableError = await evaluate(`new Promise(resolve=>chrome.management.setEnabled(${JSON.stringify(extensionId)},true,()=>resolve(chrome.runtime.lastError?.message??null)))`);
    result.after = brief((await getInfo()).find(e => e.id === extensionId));
    if (!result.enableError || result.after?.state !== 'DISABLED')
      throw new Error('The baseline unexpectedly enabled the unverified off-store extension');
  } else if (action === 'restore') {
    // Branded Chrome can report NOT_VERIFIED first; MV2 eligibility must still be restored.
    if (!extension || extension.state !== 'DISABLED' ||
        !(extension.isAffectedByMV2Deprecation || extension.disableReasons?.unsupportedManifestVersion))
      throw new Error('Removing the patch must restore MV2 deprecation: ' + JSON.stringify(brief(extension)));
    result.enableError = await evaluate(`new Promise(resolve=>chrome.management.setEnabled(${JSON.stringify(extensionId)},true,()=>resolve(chrome.runtime.lastError?.message??null)))`);
    if (!result.enableError) throw new Error('Restored Chrome unexpectedly allowed enabling MV2');
  }
  if (testUrl) {
    const opened = await browser.call('Target.createTarget', {url: testUrl});
    if (opened.error) throw new Error(JSON.stringify(opened.error));
  }
  result.processes = (await browser.call('SystemInfo.getProcessInfo')).result.processInfo;
  console.log(JSON.stringify(result)); client.ws.close(); browser.ws.close();
}
