const ws = new WebSocket("ws://127.0.0.1:8080")

console.log("web socket:", ws);

ws.onopen = (e) => {
	console.log("socket opened:", e)
}

ws.onmessage = (e) => {
	console.log("socket messaged:", e)
}

ws.onerror = (e) => {
	console.log("socket errored:", e)
}

ws.onclose = (e) => {
	console.log("socket closed:", e)
}
