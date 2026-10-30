// WebAssembly 변환 엔진을 화면과 분리된 스레드에서 실행한다 (PFX 암호화 등 무거운 작업 중에도 화면이 멈추지 않도록).
importScripts('wasm_exec.js');

const ready = (async () => {
	const go = new Go();
	let result;
	try {
		result = await WebAssembly.instantiateStreaming(fetch('sslconverter.wasm'), go.importObject);
	} catch (e) {
		// 서버가 .wasm 을 application/wasm 으로 보내지 않는 경우
		const bytes = await (await fetch('sslconverter.wasm')).arrayBuffer();
		result = await WebAssembly.instantiate(bytes, go.importObject);
	}
	go.run(result.instance);
})();

self.onmessage = async (event) => {
	const { id, op, request } = event.data;
	try {
		await ready;
		const result = await self.sslConverter[op](request);
		self.postMessage({ id, result }, result.data ? [result.data.buffer] : []);
	} catch (e) {
		self.postMessage({ id, error: String((e && e.message) || e) });
	}
};
