/** 
	 @type {WebSocket}
**/
let ws;
let retryCount = 0;
const msgInput = document.getElementById("msg");
const sendBtn = document.getElementById("send");
const msgBox = document.getElementById("msg-box");

const addMessage = (msg) => {
	msgBox.innerHTML += `<p style="margin:0px; padding: 5px 10px;border:1px solid black;">${msg}</p>`;
}

if (!ws) {
	while (retryCount < 5 && !ws) {
		ws = new WebSocket("ws://127.0.0.1:8080");
		retryCount++;
	}
	retryCount = 0;
	console.log("web socket not created");
}

console.log("web socket:", ws);

ws.onopen = (e) => {
	console.log("socket opened:", e)
}

ws.onmessage = (e) => {
	// xss me daddy
	addMessage("server: " + e.data);
	console.log("socket messaged:", e)
}

ws.onerror = (e) => {
	console.log("socket errored:", e)
}

ws.onclose = (e) => {
	console.log("socket closed:", e)
}

msgInput.addEventListener("keyup", (e) => {
	e.preventDefault();
	if (e.key === "Enter") {
		if (msgInput.value === "") return;
		ws.send(msgInput.value);
		addMessage("me: " + msgInput.value);
		msgInput.value = "";
	}
})

sendBtn.addEventListener("click", (e) => {
	e.preventDefault();
	if (msgInput.value === "") return;
	ws.send(msgInput.value);
	addMessage("me: " + msgInput.value);
	msgInput.value = "";
})
