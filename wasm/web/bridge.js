// 브라우저 전용(WebAssembly) 판에서 app.js 의 서버 API 호출을 대신한다.
// app.js 는 window.sslApiFetch 가 있으면 fetch 대신 사용하며, 이 함수는 서버 API 와 같은 fetch Response 를 돌려준다.
(() => {
	// 폐기 여부(OCSP/CRL) 확인은 CA 서버가 CORS 를 허용하지 않아 브라우저에서 할 수 없으므로 옵션을 숨긴다
	const revocation = document.getElementById('checkRevocation');
	if (revocation) {
		revocation.checked = false;
		revocation.closest('label').hidden = true;
	}

	const worker = new Worker('worker.js');
	const pending = new Map();
	let sequence = 0;

	worker.onmessage = (event) => {
		const { id, result, error } = event.data;
		const call = pending.get(id);
		pending.delete(id);
		if (error) call.reject(new Error(error));
		else call.resolve(result);
	};
	worker.onerror = (event) => {
		const error = new Error('변환 엔진(WebAssembly)을 불러오지 못했습니다: ' + (event.message || ''));
		pending.forEach((call) => call.reject(error));
		pending.clear();
	};

	function call(op, request) {
		return new Promise((resolve, reject) => {
			const id = ++sequence;
			pending.set(id, { resolve, reject });
			worker.postMessage({ id, op, request });
		});
	}

	async function toRequest(formData) {
		const request = { files: [], formats: [] };
		for (const [key, value] of formData.entries()) {
			if (key === 'files') {
				request.files.push({ name: value.name, data: new Uint8Array(await value.arrayBuffer()) });
			} else if (key === 'formats') {
				request.formats.push(value);
			} else {
				request[key] = String(value);
			}
		}
		return request;
	}

	function json(body, status) {
		return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
	}

	window.sslApiFetch = async (url, init) => {
		const op = url.endsWith('analyze') ? 'analyze' : 'convert';
		const result = await call(op, await toRequest(init.body));
		if (!result.ok) return json({ message: result.message }, result.status);
		if (op === 'analyze') {
			return new Response(result.json, { status: 200, headers: { 'Content-Type': 'application/json' } });
		}
		return new Response(new Blob([result.data], { type: result.contentType }), {
			status: 200,
			headers: {
				'Content-Type': result.contentType,
				'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(result.fileName)}`,
			},
		});
	};
})();
