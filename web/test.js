
console.log("hej hej");

var ws = new WebSocket("ws://localhost:8080/myconn")

ws.onopen = function() {
  console.log('open')
}
ws.onclose = function() {
  console.log('close')
}
ws.onerror = function(e) {
  console.log('error: ', e)
}
var msg;
ws.onmessage = function(e) {
  console.log('msg: ', e)
  msg = e
}