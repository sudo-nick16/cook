let ws = new WebSocket("ws://127.0.0.1:8080");
let retryCount = 0;

if (!ws) {
	while (retryCount < 5 && !ws) {
		ws = new WebSocket("ws://127.0.0.1:8080");
	}
	retryCount = 0;
	console.log("web socket not created");
}

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

const msgInput = document.getElementById("msg");
const sendBtn = document.getElementById("send");

msgInput.addEventListener("keyup", (e) => {
	e.preventDefault();
	if (e.key === "Enter") {
		if (msgInput.value === "") return;
		ws.send(msgInput.value);
		msgInput.value = "";
	}
})

sendBtn.addEventListener("click", (e) => {
	e.preventDefault();
	if (msgInput.value === "") return;
	ws.send(msgInput.value);
	msgInput.value = "";
})
