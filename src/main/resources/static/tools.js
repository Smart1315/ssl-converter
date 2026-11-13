(() => {
	const apiFetch = (url, init) => (window.sslApiFetch ? window.sslApiFetch(url, init) : fetch(url, init));
	const definitions = [
		{id: 'self-signed', title: '자체 서명 인증서 / 사설 CA', description: 'RSA 또는 EC 키와 자체 서명 서버 인증서 또는 사설 루트 CA를 생성합니다.', warning: '개인키는 암호화되지 않은 PKCS#8 PEM으로 내려받습니다. 안전하게 보관하세요.', fields: [
			['commonName', '공통 이름 (CN)', 'text', 'example.com'], ['keyType', '키 알고리즘', 'select', [['RSA', 'RSA'], ['EC', 'ECDSA P-256']]], ['keyBits', 'RSA 키 길이', 'select', [['2048', '2048'], ['3072', '3072'], ['4096', '4096']]], ['san', 'SAN (쉼표로 구분)', 'text', 'example.com'], ['isCa', '인증서 유형', 'select', [['false', '서버 인증서'], ['true', '사설 루트 CA']]]] },
		{id: 'csr', title: 'CSR 및 키 생성', description: 'RSA 또는 EC 개인키와 인증서 서명 요청(CSR)을 생성합니다.', fields: [
			['commonName', '공통 이름 (CN)', 'text', 'example.com'], ['keyType', '키 알고리즘', 'select', [['RSA', 'RSA'], ['EC', 'ECDSA P-256']]], ['keyBits', 'RSA 키 길이', 'select', [['2048', '2048'], ['3072', '3072'], ['4096', '4096']]], ['san', 'SAN (쉼표로 구분)', 'text', 'example.com, www.example.com']]},
		{id: 'csr-decode', title: 'CSR 디코딩', description: 'CSR 내용을 읽고 요청 서명을 검증합니다.', fields: [['files', 'CSR 파일', 'file'], ['text', 'CSR PEM 또는 DER', 'textarea']]},
		{id: 'issue', title: '사설 CA 발급', description: 'CA 인증서와 키로 CSR에 서명해 서버 인증서를 발급합니다.', warning: 'CA 개인키를 서버에 업로드합니다. 신뢰할 수 있는 개인 배포본에서만 사용하세요.', fields: [['files', 'CSR 파일', 'file'], ['text', 'CSR PEM', 'textarea'], ['caFiles', 'CA 인증서 및 개인키', 'file'], ['caText', 'CA 인증서 및 개인키 PEM', 'textarea'], ['caPassword', 'CA 키 비밀번호', 'password'], ['days', '유효 기간 (일, 최대 825)', 'text', '365']]},
		{id: 'match', title: '인증서·키·CSR 짝 확인', description: '공개키를 비교해 인증서와 개인키 또는 CSR의 짝을 확인합니다.', fields: [['files', '인증서/개인키 파일', 'file'], ['text', '인증서/개인키 PEM', 'textarea'], ['csrText', '비교할 CSR PEM (선택)', 'textarea'], ['password', '개인키 비밀번호', 'password']]},
		{id: 'crl', title: 'CRL 보기', description: 'CRL 발급자, 갱신 시각, 폐기 인증서 목록과 서명을 확인합니다.', fields: [['files', 'CRL 파일', 'file'], ['text', 'CRL PEM 또는 DER', 'textarea'], ['issuerFiles', '발급자 인증서 (서명 검증용)', 'file'], ['issuerText', '발급자 인증서 PEM', 'textarea']]},
		{id: 'ocsp', title: 'OCSP 응답 해석', description: 'OCSP 상태와 응답 시각을 표시합니다. 발급자 인증서를 제공하면 서명도 검증합니다.', fields: [['files', 'OCSP 응답 파일', 'file'], ['text', 'OCSP 응답 DER', 'textarea'], ['issuerFiles', '발급자 인증서 (선택)', 'file'], ['issuerText', '발급자 인증서 PEM (선택)', 'textarea']]},
		{id: 'asn1', title: 'ASN.1 / DER 구조 보기', description: '입력 DER의 ASN.1 태그와 계층 구조를 표시합니다. 최대 500개 노드까지 표시합니다.', fields: [['files', 'DER 파일', 'file'], ['text', 'DER Base64 또는 PEM', 'textarea']]},
		{id: 'compare', title: '인증서 비교', description: '두 인증서의 주체, 발급자, 유효 기간, 키 알고리즘과 SAN을 비교합니다.', fields: [['files', '이전 인증서 파일', 'file'], ['text', '이전 인증서 PEM', 'textarea'], ['filesB', '현재 인증서 파일', 'file'], ['textB', '현재 인증서 PEM', 'textarea']]},
		{id: 'cms', title: 'PKCS#7 / CMS 서명 확인', description: '포함 또는 분리 CMS 서명의 cryptographic signature를 확인합니다. 인증서 체인 신뢰성은 별도입니다.', fields: [['files', 'CMS 파일', 'file'], ['text', 'CMS PEM 또는 DER', 'textarea'], ['contentFiles', '분리 서명 원본 파일 (선택)', 'file'], ['contentText', '분리 서명 원본 텍스트 (선택)', 'textarea']]},
		{id: 'tls', title: '원격 TLS 점검', description: '공개 인터넷 TLS 서버에 연결해 인증서 체인과 TLS 핸드셰이크를 확인합니다.', warning: '서버 판 전용입니다. 외부 호스트에 연결합니다. 사설/로컬 주소는 차단됩니다.', fields: [['host', '호스트 이름', 'text', 'example.com'], ['port', '포트', 'text', '443']]},
	];
	const tabs = document.getElementById('tool-tabs');
	const form = document.getElementById('tool-form');
	const output = document.getElementById('tool-output');
	let current;

	function makeField([name, label, type, extra]) {
		const wrapper = document.createElement('label');
		wrapper.className = 'field tool-field';
		const caption = document.createElement('span'); caption.textContent = label; wrapper.append(caption);
		let control;
		if (type === 'select') {
			control = document.createElement('select');
			extra.forEach(([value, text]) => { const option = document.createElement('option'); option.value = value; option.textContent = text; control.append(option); });
		} else if (type === 'textarea') {
			control = document.createElement('textarea'); control.rows = 5; control.placeholder = '여기에 내용을 붙여 넣으세요';
		} else {
			control = document.createElement('input'); control.type = type;
			if (type === 'file') { control.multiple = true; control.accept = '.pem,.crt,.cer,.der,.csr,.crl,.p7b,.p7c,.p7s,.p12,.pfx'; }
			if (extra) control.placeholder = extra;
		}
		control.name = name;
		wrapper.append(control);
		return wrapper;
	}

	function selectTool(definition) {
		current = definition;
		tabs.querySelectorAll('button').forEach(button => button.classList.toggle('active', button.dataset.id === definition.id));
		document.getElementById('tool-title').textContent = definition.title;
		document.getElementById('tool-description').textContent = definition.description;
		const warning = document.getElementById('tool-warning'); warning.hidden = !definition.warning; warning.textContent = definition.warning || '';
		form.replaceChildren();
		const fields = document.createElement('div'); fields.className = 'options';
		definition.fields.forEach(field => fields.append(makeField(field)));
		form.append(fields);
		const actions = document.createElement('div'); actions.className = 'actions';
		const submit = document.createElement('button'); submit.className = 'primary'; submit.type = 'submit'; submit.textContent = '실행';
		const status = document.createElement('span'); status.className = 'muted'; status.id = 'tool-status';
		actions.append(submit, status); form.append(actions);
		output.hidden = true;
	}

	function renderTree(node, parent) {
		if (!node || typeof node !== 'object') return;
		const item = document.createElement('li');
		item.textContent = `${node.name || ''}: ${node.value || ''}`;
		parent.append(item);
		if (Array.isArray(node.children) && node.children.length) {
			const list = document.createElement('ul'); item.append(list);
			node.children.forEach(child => renderTree(child, list));
		}
	}

	function render(result) {
		output.replaceChildren(); output.hidden = false;
		(result.messages || []).forEach(message => { const paragraph = document.createElement('p'); paragraph.className = 'msg info'; paragraph.textContent = message; output.append(paragraph); });
		(result.sections || []).forEach(section => {
			const article = document.createElement('section'); article.className = 'tool-result-section';
			const heading = document.createElement('h3'); heading.textContent = section.title; article.append(heading);
			const list = document.createElement('dl');
			(section.rows || []).forEach(row => { const term = document.createElement('dt'); term.textContent = row.label; const value = document.createElement('dd'); value.textContent = row.value; list.append(term, value); });
			article.append(list); output.append(article);
		});
		(result.files || []).forEach(file => {
			const section = document.createElement('section'); section.className = 'tool-result-section';
			const title = document.createElement('h3'); title.textContent = file.name; section.append(title);
			const content = document.createElement('textarea'); content.readOnly = true; content.rows = Math.min(16, Math.max(4, file.content.split('\n').length)); content.value = file.content; section.append(content);
			const download = document.createElement('button'); download.type = 'button'; download.textContent = '다운로드';
			download.addEventListener('click', () => { const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([file.content], {type: 'text/plain;charset=utf-8'})); link.download = file.name; link.click(); URL.revokeObjectURL(link.href); }); section.append(download); output.append(section);
		});
		if (result.tree) { const section = document.createElement('section'); section.className = 'tool-result-section'; const heading = document.createElement('h3'); heading.textContent = 'ASN.1 트리'; section.append(heading); const list = document.createElement('ul'); list.className = 'asn1-tree'; renderTree(result.tree, list); section.append(list); output.append(section); }
	}

	definitions.forEach(definition => {
		const button = document.createElement('button'); button.type = 'button'; button.textContent = definition.title; button.dataset.id = definition.id;
		button.addEventListener('click', () => selectTool(definition)); tabs.append(button);
	});
	form.addEventListener('submit', async event => {
		event.preventDefault();
		const submit = form.querySelector('button[type=submit]'); const status = document.getElementById('tool-status'); submit.disabled = true; status.textContent = '처리 중…';
		try {
			const response = await apiFetch(`api/tools/${current.id}`, {method: 'POST', body: new FormData(form)});
			const result = await response.json();
			if (!response.ok) throw new Error(result.message || '요청 처리에 실패했습니다.');
			render(result); status.textContent = '완료';
		} catch (error) { output.hidden = false; output.replaceChildren(); const message = document.createElement('p'); message.className = 'msg error'; message.textContent = error.message; output.append(message); status.textContent = '오류'; }
		finally { submit.disabled = false; }
	});

	function updateAvailability() {
		if (window.sslWasm) {
			const tls = definitions.findIndex(item => item.id === 'tls'); if (tls >= 0) definitions.splice(tls, 1);
			tabs.querySelectorAll('[data-id="tls"]').forEach(button => button.remove());
		}
	}
	updateAvailability();
	selectTool(definitions[0]);
})();
