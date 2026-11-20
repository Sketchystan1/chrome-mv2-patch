// Drive the real download/open path; package verification and native confirmation
// remain in Chrome. UI confirmation is performed separately on a private desktop.
import fs from 'node:fs';
const [profile, action, extensionId, value] = process.argv.slice(2);
const [port, browserPath] = fs.readFileSync(profile + '/DevToolsActivePort', 'utf8').trim().split('\n');
async function connect(url) {
  const ws = new WebSocket(url);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = event => {
    const reply = JSON.parse(event.data), entry = pending.get(reply.id);
    if (entry) { clearTimeout(entry.timer); pending.delete(reply.id); entry.resolve(reply); }
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
const browserVersion = await browser.call('Browser.getVersion');
const scheme = /\bEdg\//.test(browserVersion.result?.userAgent ?? '') ? 'edge' : 'chrome';
const downloadsUrl = scheme + '://downloads/';
if (action === 'close') {
  await browser.call('Browser.close'); browser.ws.close();
} else {
  if (action === 'mv3') {
    const loaded = await browser.call('Extensions.loadUnpacked', {path: value});
    if (loaded.error || !loaded.result?.id) throw new Error(JSON.stringify(loaded));
    console.log(JSON.stringify(loaded.result)); browser.ws.close();
  } else {
    const url = ['downloads', 'open', 'keep'].includes(action) ? downloadsUrl :
      action === 'download' ? value : action === 'probe' ? value : scheme + '://extensions/';
    let targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const targetFile = profile + '/crx-download-target';
    let target = url === downloadsUrl && fs.existsSync(targetFile) ?
      targets.find(item => item.id === fs.readFileSync(targetFile, 'utf8').trim()) :
      targets.find(item => item.type === 'page' && item.url === url);
    if (url === downloadsUrl && !target) throw new Error('Original download tab is unavailable');
    if (!target) target = await (await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(url)}`, {method: 'PUT'})).json();
    if (action === 'download') fs.writeFileSync(targetFile, target.id);
    const client = await connect(target.webSocketDebuggerUrl);
    if (target.url !== url) await client.call('Page.navigate', {url});
    await browser.call('Target.activateTarget', {targetId: target.id});
    async function evaluate(expression) {
      const reply = await client.call('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true, userGesture: true});
      if (reply.error || reply.result?.exceptionDetails) throw new Error(JSON.stringify(reply));
      return reply.result?.result?.value;
    }
    for (let attempt = 0; attempt < 30; ++attempt) {
      const ready = action === 'download' ? 'document.readyState === "complete" && !!document.querySelector("a#download")' :
        ['downloads', 'open', 'keep'].includes(action) ? `document.readyState === "complete" && !!document.querySelector("${scheme === 'edge' ? 'downloads-full-page-app' : 'downloads-manager'}")` :
        action === 'info' || action === 'enable' ? 'document.readyState === "complete" && !!chrome.developerPrivate' : 'document.readyState === "complete"';
      if (await evaluate(ready)) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    let result;
    async function clickControl(selector, warning = false) {
      let point;
      for (let attempt = 0; attempt < 50; ++attempt) {
        const match = warning ? `node.tagName==='${scheme === 'edge' ? 'DOWNLOADS-MODAL-DIALOG' : 'DOWNLOADS-BYPASS-WARNING-CONFIRMATION-DIALOG'}'` :
          scheme === 'edge' ? "node.tagName==='DOWNLOAD-ITEM'&&node.id===" + JSON.stringify(value) : "node.tagName==='DOWNLOADS-ITEM'&&node.data?.id===" + JSON.stringify(value);
        point = await evaluate(`(()=>{function find(root){for(const node of root.querySelectorAll('*')){if(${match})return node;if(node.shadowRoot){const found=find(node.shadowRoot);if(found)return found}}}const item=find(document);const link=item?.shadowRoot?.querySelector(${JSON.stringify(selector)});if(!link||link.disabled)return null;link.scrollIntoView({block:'center'});const r=link.getBoundingClientRect();return{x:r.left+r.width/2,y:r.top+r.height/2,width:r.width,height:r.height}})()`);
        if (point?.width && point?.height) break;
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      if (!point?.width || !point?.height) throw new Error('Download control has empty bounds: ' + selector);
      for (const type of ['mouseMoved', 'mousePressed', 'mouseReleased']) {
        const reply = await client.call('Input.dispatchMouseEvent', {type,x:point.x,y:point.y,button:'left',clickCount:1});
        if (reply.error) throw new Error(JSON.stringify(reply));
      }
    }
    if (action === 'download') {
      const point = await evaluate('(()=>{const r=document.querySelector("a#download").getBoundingClientRect();return{x:r.left+r.width/2,y:r.top+r.height/2}})()');
      for (const type of ['mouseMoved', 'mousePressed', 'mouseReleased']) {
        const reply = await client.call('Input.dispatchMouseEvent', {type,...point,button:'left',clickCount:1});
        if (reply.error) throw new Error(JSON.stringify(reply));
      }
      result = true;
    } else if (action === 'downloads') {
      result = scheme === 'edge' ? await evaluate(`(()=>{const items=[];function walk(root){for(const node of root.querySelectorAll('*')){if(node.tagName==='DOWNLOAD-ITEM'){const icon=node.icon??node._icon;const path=icon?.startsWith('edge://fileicon/')?new URL(icon).searchParams.get('path'):null;items.push({id:node.id,fileName:path?path.replace(/^.*[\\\\/]/,''):node.title?.match(/^.*?\\.crx/)?.[0],filePath:path,state:node.state,isDangerous:node.state?.startsWith('dangerous')})}if(node.shadowRoot)walk(node.shadowRoot)}}walk(document);return{items}})()`) :
        await evaluate(`(()=>{const manager=document.querySelector('downloads-manager');const items=manager?.items_??manager?.items;return {items:items?.map(item=>({id:item.id,fileName:item.fileName,filePath:item.filePath,state:item.state,isDangerous:item.isDangerous,isInsecure:item.isInsecure,dangerType:item.dangerType,url:item.url}))??[]}})()`);
    } else if (action === 'keep') {
      if (scheme === 'edge') {
        await clickControl('[data-action="keepDangerous"]');
        result = true;
      } else {
      await clickControl('#more-actions');
      await clickControl('#save-dangerous');
      let saved = false;
      for (let attempt = 0; attempt < 50; ++attempt) {
        const status = await evaluate(`(()=>{const manager=document.querySelector('downloads-manager');const item=manager.items_.find(item=>item.id===${JSON.stringify(value)});return{warning:!!manager.shadowRoot.querySelector('downloads-bypass-warning-confirmation-dialog'),saved:!!item&&!item.isDangerous&&!item.isInsecure}})()`);
        if (status.warning) { await clickControl('#download-dangerous-button', true); saved = true; break; }
        if (status.saved) { saved = true; break; }
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      if (!saved) throw new Error('Download warning was not confirmed');
      result = true;
      }
    } else if (action === 'open') {
      // Downloads checks real input interaction separately from V8's gesture
      // flag. Dispatch a click to the actual file link in this browser page.
      await clickControl(scheme === 'edge' ? '[data-action="openFile"],[data-action="open"]' : '#fileLink');
      result = true;
    } else if (action === 'probe') {
      result = true;
    } else {
      const getInfo = () => evaluate('new Promise(resolve=>chrome.developerPrivate.getExtensionsInfo({includeDisabled:true,includeTerminated:true},resolve))');
      let extension = (await getInfo()).find(item => item.id === extensionId);
      if (action === 'enable') {
        if (!extension || extension.location === 'UNPACKED' || extension.isAffectedByMV2Deprecation || extension.disableReasons?.unsupportedManifestVersion)
          throw new Error('Expected an eligible packed MV2 extension: ' + JSON.stringify(extension));
        for (const enabled of [false, true]) {
          const error = await evaluate(`new Promise(resolve=>chrome.management.setEnabled(${JSON.stringify(extensionId)},${enabled},()=>resolve(chrome.runtime.lastError?.message??null)))`);
          if (error) throw new Error(error);
          extension = (await getInfo()).find(item => item.id === extensionId);
          if (extension.state !== (enabled ? 'ENABLED' : 'DISABLED')) throw new Error('Enable/disable failed');
        }
      }
      result = {extension: extension && {id:extension.id,name:extension.name,state:extension.state,location:extension.location,
        isAffectedByMV2Deprecation:extension.isAffectedByMV2Deprecation,disableReasons:extension.disableReasons,
        manifestErrors:extension.manifestErrors,runtimeErrors:extension.runtimeErrors},
        processes:(await browser.call('SystemInfo.getProcessInfo')).result.processInfo};
    }
    console.log(JSON.stringify(result)); client.ws.close(); browser.ws.close();
  }
}
