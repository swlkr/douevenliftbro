if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/static/sw.js', { scope: '/' })
    .then(reg => {
      reg.addEventListener('statechange', event => {
        console.log("received `statechange` event", { reg, event })
      });
      console.log("service worker registered", reg);
      setTimeout(() => {
          reg.active.postMessage({ type: 'clientattached' });
      }, 100);
    }).catch(err => {
      console.error("service worker registration failed", err);
    });
  navigator.serviceWorker.addEventListener('controllerchange', event => {
    console.log("received `controllerchange` event", event);
  });
} else {
  console.error("serviceWorker is missing from `navigator`. Note service workers must be served over https or on localhost");
}
