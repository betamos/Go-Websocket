
console.log("hej hej");

var ws = new WebSocket("ws://localhost:8080/myconn")

setTimeout(function() {
  ws.send("Hello from client\n")
}, 500)

setTimeout(function() {
  //ws.close()
}, 1000)

ws.onopen = function() {
  console.log('open')
}
ws.onclose = function(e) {
  console.log('close', e)
}
ws.onerror = function(e) {
  console.log('error: ', e)
}
var msg;
ws.onmessage = function(e) {
  console.log('msg: ', e)
  msg = e
}