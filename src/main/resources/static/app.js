'use strict';

const FORMATS = [
	{ id: 'FULLCHAIN_PEM', name: '풀체인 PEM', file: '{b}_fullchain.pem', desc: '서버 인증서 + 중간(+루트). Nginx ssl_certificate, 기존 cat 으로 만들던 .pem' },
	{ id: 'KEY_PEM', name: '개인키 PEM', file: '{b}.key', desc: 'Nginx ssl_certificate_key, Apache SSLCertificateKeyFile', key: true },
	{ id: 'CERT_PEM', name: '서버 인증서 PEM', file: '{b}.crt', desc: '서버 인증서 단독. Apache SSLCertificateFile' },
	{ id: 'CHAIN_PEM', name: '체인(CA 번들) PEM', file: '{b}_chain.crt', desc: '중간(+루트)만. Apache SSLCertificateChainFile / SSLCACertificateFile' },
	{ id: 'PFX', name: 'PKCS#12 (PFX/P12)', file: '{b}.pfx', desc: 'IIS, Windows, Tomcat, Spring Boot, Azure 등. 키+체인 포함', pw: true },
	{ id: 'JKS', name: 'Java KeyStore (JKS)', file: '{b}.jks', desc: 'Tomcat, WebLogic, JEUS 등 Java WAS. 키+체인 포함', pw: true },
	{ id: 'COMBINED_PEM', name: '키+풀체인 통합 PEM', file: '{b}_combined.pem', desc: 'HAProxy, 일부 L4/로드밸런서, Webmin', key: true },
	{ id: 'P7B', name: 'PKCS#7 (P7B)', file: '{b}.p7b', desc: '인증서 체인만 (키 없음). Windows 인증서 가져오기, IIS 인증서 요청 완료' },
	{ id: 'DER', name: 'DER 인증서 (CER)', file: '{b}.cer', desc: '바이너리 서버 인증서. Windows 더블클릭 확인, Java keytool -importcert' },
	{ id: 'TRUSTSTORE_JKS', name: '트러스트스토어 (JKS)', file: '{b}_truststore.jks', desc: '체인(CA) 인증서만. 클라이언트 측에서 이 서버를 신뢰할 때', pw: true },
];

const PRESETS = {
	nginx: ['FULLCHAIN_PEM', 'KEY_PEM'],
	apache: ['CERT_PEM', 'CHAIN_PEM', 'KEY_PEM'],
	tomcat: ['PFX', 'JKS'],
	iis: ['PFX'],
	haproxy: ['COMBINED_PEM'],
	all: FORMATS.map((f) => f.id),
	none: [],
};

const state = {
	files: [],
	analysis: null,
	analyzeSeq: 0,
	guide: 'nginx',
	baseNameTouched: false,
	aliasTouched: false,
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ------------------------------------------------------------------ input

function addFiles(list) {
	for (const file of list) {
		const exists = state.files.some((f) => f.name === file.name && f.size === file.size && f.lastModified === file.lastModified);
		if (!exists) state.files.push(file);
	}
	renderFiles();
	scheduleAnalyze(0);
}

function renderFiles() {
	$('fileList').innerHTML = state.files.map((f, i) =>
		`<li>${esc(f.name)} <small>${formatSize(f.size)}</small><button type="button" data-remove="${i}" title="제거">×</button></li>`).join('');
}

function formatSize(n) {
	return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`;
}

function inputFormData() {
	const fd = new FormData();
	state.files.forEach((f) => fd.append('files', f, f.name));
	const text = $('pasteText').value;
	if (text.trim()) fd.append('text', text);
	const pw = $('inPassword').value;
	if (pw) fd.append('password', pw);
	const alias = $('aliasField').hidden ? '' : $('inAlias').value;
	if (alias) fd.append('alias', alias);
	return fd;
}

function hasInput() {
	return state.files.length > 0 || $('pasteText').value.trim() !== '';
}

// ------------------------------------------------------------------ analyze

let analyzeTimer;
function scheduleAnalyze(delay = 500) {
	clearTimeout(analyzeTimer);
	analyzeTimer = setTimeout(analyze, delay);
}

async function analyze() {
	if (!hasInput()) {
		state.analysis = null;
		$('analysisCard').hidden = $('outputCard').hidden = $('guideCard').hidden = true;
		$('aliasField').hidden = true;
		return;
	}
	const seq = ++state.analyzeSeq;
	$('analysisCard').hidden = false;
	$('analyzing').hidden = false;
	try {
		const fd = inputFormData();
		if ($('checkRevocation').checked) fd.append('checkRevocation', 'true');
		const res = await fetch('api/analyze', { method: 'POST', body: fd });
		const data = await res.json();
		if (seq !== state.analyzeSeq) return;
		if (!res.ok) throw new Error(data.message || res.statusText);
		state.analysis = data;
		renderAnalysis(data);
	} catch (e) {
		if (seq !== state.analyzeSeq) return;
		state.analysis = null;
		$('messages').innerHTML = `<div class="msg error">${esc(e.message)}</div>`;
		$('sources').innerHTML = $('chain').innerHTML = $('unrelated').innerHTML = $('checklist').innerHTML = '';
		$('outputCard').hidden = $('guideCard').hidden = true;
	} finally {
		if (seq === state.analyzeSeq) $('analyzing').hidden = true;
	}
}

const CHECK_ICONS = { PASS: '✔', WARN: '!', FAIL: '✖', SKIPPED: '–' };

function renderChecklist(checks) {
	if (!checks || !checks.length) {
		$('checklist').innerHTML = '';
		return;
	}
	const count = (s) => checks.filter((c) => c.status === s).length;
	const fail = count('FAIL');
	const warn = count('WARN');
	const head = fail ? `<span style="color:var(--err)">문제 ${fail}건</span>${warn ? ` · 확인 필요 ${warn}건` : ''}`
		: warn ? `<span style="color:var(--warn)">확인 필요 ${warn}건</span>` : '<span style="color:var(--ok)">모든 점검 통과</span>';
	$('checklist').innerHTML = `<div class="checklist-head"><span>점검 결과</span><small>${head}</small></div>`
		+ checks.map((c) => `<div class="check ${c.status}">
			<span class="icon">${CHECK_ICONS[c.status] || ''}</span>
			<span class="title">${esc(c.title)}</span>
			<span class="detail">${esc(c.summary)}${c.details.length ? `<ul>${c.details.map((d) => `<li>${esc(d)}</li>`).join('')}</ul>` : ''}</span>
		</div>`).join('');
}

function renderAnalysis(a) {
	renderChecklist(a.checks);
	const msgs = [];
	a.errors.forEach((m) => msgs.push(`<div class="msg error">${esc(m)}</div>`));
	a.warnings.forEach((m) => msgs.push(`<div class="msg warn">⚠ ${esc(m)}</div>`));
	a.notices.forEach((m) => msgs.push(`<div class="msg info">${esc(m)}</div>`));
	$('messages').innerHTML = msgs.join('');

	$('sources').innerHTML = a.sources.map((s) => {
		const found = [s.certificates ? `인증서 ${s.certificates}` : '', s.privateKeys ? `개인키 ${s.privateKeys}` : ''].filter(Boolean).join(', ');
		return `<div class="source"><b>${esc(s.name)}</b> — ${esc(s.format || '?')}${found ? ` · ${found}` : ''}
			${s.notes.length ? `<span class="notes">${s.notes.map(esc).join('<br>')}</span>` : ''}</div>`;
	}).join('');

	renderAliasSelect(a);

	const b = a.bundle;
	if (!b) {
		$('chain').innerHTML = $('unrelated').innerHTML = $('checklist').innerHTML = '';
		$('outputCard').hidden = $('guideCard').hidden = true;
		return;
	}

	const keyBadge = b.privateKey
		? `<span class="badge ok">🔑 개인키 일치 · ${esc(b.privateKey.description)}</span>`
		: '<span class="badge warn">개인키 없음</span>';
	$('chain').innerHTML = b.certificates.map((c, i) => certCard(c, i === 0, i === 0 ? keyBadge : '')).join('<div class="link">▲ 위 인증서를 발급</div>');

	$('unrelated').innerHTML = b.unrelated.length
		? `<h3 class="muted" style="font-size:13px;margin:14px 0 6px">체인에 속하지 않는 인증서 (출력 제외)</h3>${b.unrelated.map((c) => certCard(c, false, '')).join('')}`
		: '';

	if (!state.baseNameTouched) $('baseName').value = a.suggestedBaseName || '';
	if (!state.aliasTouched) $('outAlias').value = a.suggestedAlias || '';

	$('outputCard').hidden = false;
	$('guideCard').hidden = false;
	updateFormatAvailability();
	updateFileNames();
}

function renderAliasSelect(a) {
	const keyEntries = a.keystoreEntries.filter((e) => e.type === 'PrivateKeyEntry');
	if (keyEntries.length > 1) {
		const current = $('inAlias').value || a.selectedAlias;
		$('inAlias').innerHTML = keyEntries.map((e) =>
			`<option value="${esc(e.alias)}" ${e.alias === current ? 'selected' : ''}>${esc(e.alias)} (${esc(e.source)})</option>`).join('');
		$('aliasField').hidden = false;
	} else if (!$('aliasField').hidden && keyEntries.length <= 1) {
		$('aliasField').hidden = true;
		$('inAlias').innerHTML = '';
	}
}

const STATUS = {
	VALID: ['ok', '유효'],
	EXPIRING: ['warn', '곧 만료'],
	EXPIRED: ['err', '만료됨'],
	NOT_YET_VALID: ['warn', '유효기간 전'],
};

function certCard(c, leaf, extra) {
	const [cls, label] = STATUS[c.status] || ['', c.status];
	const days = c.status === 'EXPIRED' ? `${-c.daysRemaining}일 지남` : `${c.daysRemaining}일 남음`;
	const san = c.subjectAltNames.length ? `<dt>SAN</dt><dd>${c.subjectAltNames.map(esc).join(', ')}</dd>` : '';
	const aia = c.caIssuersUrl ? `<dt>발급자 인증서</dt><dd>${esc(c.caIssuersUrl)}</dd>` : '';
	return `<div class="cert ${leaf ? 'leaf' : ''}">
		<div class="cert-head" data-toggle>
			<span class="badge role">${esc(c.role)}</span>
			<span class="cn">${esc(c.commonName || c.subject)}</span>
			<span class="badge ${cls}">${label} · ${days}</span>
			${extra}
		</div>
		<div class="cert-meta">${esc(c.notBefore)} ~ ${esc(c.notAfter)} · ${esc(c.publicKey)} · 발급자: ${esc(shortIssuer(c.issuer))}</div>
		<dl hidden>
			<dt>소유자</dt><dd>${esc(c.subject)}</dd>
			<dt>발급자</dt><dd>${esc(c.issuer)}</dd>
			${san}
			<dt>일련번호</dt><dd>${esc(c.serialNumber)}</dd>
			<dt>서명 알고리즘</dt><dd>${esc(c.signatureAlgorithm)}</dd>
			<dt>SHA-1</dt><dd>${esc(c.sha1)}</dd>
			<dt>SHA-256</dt><dd>${esc(c.sha256)}</dd>
			${aia}
		</dl>
	</div>`;
}

function shortIssuer(dn) {
	const m = /CN=([^,]+)/.exec(dn);
	return m ? m[1] : dn;
}

// ------------------------------------------------------------------ output

function renderFormats() {
	$('formats').innerHTML = FORMATS.map((f) => `
		<label class="format" data-format="${f.id}">
			<input type="checkbox" value="${f.id}">
			<span class="name">${esc(f.name)}</span>
			<span class="file" data-file="${f.file}"></span>
			<span class="desc">${esc(f.desc)}</span>
		</label>`).join('');
	applyPreset('nginx');
	updateFileNames();
}

function applyPreset(name) {
	const ids = PRESETS[name] || [];
	document.querySelectorAll('#formats input').forEach((cb) => {
		cb.checked = ids.includes(cb.value) && !cb.disabled;
	});
	updateDownloadInfo();
}

function selectedFormats() {
	return [...document.querySelectorAll('#formats input:checked')].map((cb) => cb.value);
}

function updateFileNames() {
	const base = $('baseName').value.trim() || 'certificate';
	document.querySelectorAll('#formats [data-file]').forEach((el) => {
		el.textContent = el.dataset.file.replace('{b}', base);
	});
	renderGuide();
}

function updateFormatAvailability() {
	const hasKey = !!state.analysis?.bundle?.privateKey;
	FORMATS.forEach((f) => {
		const label = document.querySelector(`.format[data-format="${f.id}"]`);
		const cb = label.querySelector('input');
		const disabled = f.key && !hasKey;
		cb.disabled = disabled;
		if (disabled) cb.checked = false;
		label.classList.toggle('disabled', disabled);
		label.title = disabled ? '일치하는 개인키가 있어야 생성할 수 있습니다' : '';
	});
	updateDownloadInfo();
}

function updateDownloadInfo() {
	const sel = selectedFormats();
	const needPw = sel.some((id) => FORMATS.find((f) => f.id === id).pw)
		|| ($('keyFormat').value === 'PKCS8_ENCRYPTED' && (sel.includes('KEY_PEM') || sel.includes('COMBINED_PEM')));
	$('pwHint').textContent = needPw ? '필수 · JKS 는 6자 이상 권장' : 'PFX/JKS/암호화 키에 사용';
	$('pwHint').style.color = needPw && !$('outPassword').value ? 'var(--err)' : '';
	$('downloadInfo').textContent = sel.length === 0 ? '형식을 선택하세요'
		: sel.length === 1 ? '파일 1개 다운로드' : `${sel.length}개 파일을 ZIP 으로 다운로드`;
	$('downloadBtn').disabled = sel.length === 0;
	const hasKey = !!state.analysis?.bundle?.privateKey;
	$('noKeyWarning').hidden = hasKey || !sel.some((id) => id === 'PFX' || id === 'JKS');
}

async function download() {
	const sel = selectedFormats();
	const errBox = $('convertError');
	errBox.hidden = true;
	const pw = $('outPassword').value;
	if (pw && pw.length < 6 && sel.includes('JKS')
		&& !confirm('JKS 비밀번호가 6자 미만이면 keytool/Tomcat 에서 거부될 수 있습니다. 계속할까요?')) {
		return;
	}
	const fd = inputFormData();
	sel.forEach((id) => fd.append('formats', id));
	fd.append('baseName', $('baseName').value.trim());
	fd.append('outAlias', $('outAlias').value.trim());
	if (pw) fd.append('outPassword', pw);
	fd.append('includeRoot', $('includeRoot').checked);
	fd.append('legacyPfx', $('legacyPfx').checked);
	fd.append('keyFormat', $('keyFormat').value);

	const btn = $('downloadBtn');
	btn.disabled = true;
	try {
		const res = await fetch('api/convert', { method: 'POST', body: fd });
		if (!res.ok) {
			const data = await res.json().catch(() => ({}));
			throw new Error(data.message || res.statusText);
		}
		const blob = await res.blob();
		const name = fileNameFrom(res.headers.get('Content-Disposition')) || 'certificate';
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = name;
		document.body.appendChild(a);
		a.click();
		a.remove();
		setTimeout(() => URL.revokeObjectURL(url), 1000);
	} catch (e) {
		errBox.textContent = e.message;
		errBox.hidden = false;
	} finally {
		btn.disabled = false;
		updateDownloadInfo();
	}
}

function fileNameFrom(header) {
	if (!header) return null;
	const star = /filename\*=UTF-8''([^;]+)/i.exec(header);
	if (star) return decodeURIComponent(star[1]);
	const plain = /filename="?([^";]+)"?/i.exec(header);
	return plain ? plain[1] : null;
}

// ------------------------------------------------------------------ guide

const GUIDES = {
	nginx: (b, a) => `server {
    listen 443 ssl;
    server_name ${a};

    ssl_certificate     /etc/nginx/ssl/${b}_fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/${b}.key;
}

# 확인: nginx -t && systemctl reload nginx`,
	apache: (b, a) => `<VirtualHost *:443>
    ServerName ${a}
    SSLEngine on
    SSLCertificateFile      /etc/httpd/ssl/${b}.crt
    SSLCertificateKeyFile   /etc/httpd/ssl/${b}.key
    # Apache 2.4.8 미만에서만 필요 (2.4.8+ 는 SSLCertificateFile 에 풀체인 사용 가능)
    SSLCertificateChainFile /etc/httpd/ssl/${b}_chain.crt
</VirtualHost>`,
	tomcat: (b, a) => `<!-- server.xml (Tomcat 8.5+) -->
<Connector port="443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           SSLEnabled="true" maxThreads="150" scheme="https" secure="true">
    <SSLHostConfig>
        <Certificate certificateKeystoreFile="conf/ssl/${b}.jks"
                     certificateKeystorePassword="비밀번호"
                     certificateKeyAlias="${a}"
                     type="RSA" />
        <!-- PFX 사용 시: certificateKeystoreFile="conf/ssl/${b}.pfx" certificateKeystoreType="PKCS12" -->
    </SSLHostConfig>
</Connector>

# 확인: keytool -list -v -keystore ${b}.jks`,
	spring: (b, a) => `# application.properties
server.port=443
server.ssl.key-store=classpath:${b}.pfx
server.ssl.key-store-type=PKCS12
server.ssl.key-store-password=비밀번호
server.ssl.key-alias=${a}
# JKS 사용 시: server.ssl.key-store=classpath:${b}.jks / key-store-type=JKS`,
	iis: (b) => `1. ${b}.pfx 를 서버에 복사
2. IIS 관리자 > 서버 > [서버 인증서] > [가져오기] 에서 PFX 선택, 비밀번호 입력
3. 사이트 > [바인딩] > https(443) > SSL 인증서 선택

※ Windows Server 2016 이하에서 "암호가 올바르지 않습니다" 오류가 나면
   'PFX 레거시 암호화 (3DES/SHA1)' 를 체크하고 다시 생성하세요.

# PowerShell 로 가져오기
Import-PfxCertificate -FilePath .\\${b}.pfx -CertStoreLocation Cert:\\LocalMachine\\My -Password (Read-Host -AsSecureString)`,
	haproxy: (b) => `frontend https
    bind *:443 ssl crt /etc/haproxy/certs/${b}_combined.pem`,
	verify: (b) => `# 인증서 정보 확인
openssl x509 -in ${b}.crt -noout -subject -issuer -dates

# 키와 인증서가 짝인지 확인 (두 값이 같아야 함)
openssl x509 -in ${b}.crt -noout -pubkey | openssl sha256
openssl pkey -in ${b}.key -pubout | openssl sha256

# PFX / JKS 내용 확인
openssl pkcs12 -in ${b}.pfx -info -nokeys
keytool -list -v -storetype PKCS12 -keystore ${b}.pfx
keytool -list -v -keystore ${b}.jks

# 실제 서버에 적용된 체인 확인
openssl s_client -connect 도메인:443 -servername 도메인 -showcerts </dev/null`,
};

const GUIDE_LABELS = { nginx: 'Nginx', apache: 'Apache', tomcat: 'Tomcat', spring: 'Spring Boot', iis: 'IIS', haproxy: 'HAProxy', verify: '확인 명령' };

function renderGuide() {
	if ($('guideCard').hidden) return;
	$('guideTabs').innerHTML = Object.keys(GUIDES).map((k) =>
		`<button type="button" data-guide="${k}" class="${k === state.guide ? 'active' : ''}">${GUIDE_LABELS[k]}</button>`).join('');
	const base = $('baseName').value.trim() || 'certificate';
	const alias = $('outAlias').value.trim() || 'certificate';
	$('guideBody').textContent = GUIDES[state.guide](base, alias);
}

// ------------------------------------------------------------------ events

function init() {
	renderFormats();

	const dz = $('dropzone');
	$('fileInput').addEventListener('change', (e) => {
		addFiles(e.target.files);
		e.target.value = '';
	});
	['dragenter', 'dragover'].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.add('over'); }));
	['dragleave', 'drop'].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.remove('over'); }));
	dz.addEventListener('drop', (e) => addFiles(e.dataTransfer.files));
	// 페이지 아무 곳에 떨어뜨려도 브라우저가 파일을 열지 않도록
	window.addEventListener('dragover', (e) => e.preventDefault());
	window.addEventListener('drop', (e) => { e.preventDefault(); if (e.dataTransfer?.files?.length) addFiles(e.dataTransfer.files); });

	$('fileList').addEventListener('click', (e) => {
		const idx = e.target.dataset.remove;
		if (idx === undefined) return;
		state.files.splice(Number(idx), 1);
		renderFiles();
		scheduleAnalyze(0);
	});
	$('pasteText').addEventListener('input', () => scheduleAnalyze(600));
	$('inPassword').addEventListener('input', () => scheduleAnalyze(600));
	$('inAlias').addEventListener('change', () => scheduleAnalyze(0));
	$('checkRevocation').addEventListener('change', () => scheduleAnalyze(0));

	$('chain').addEventListener('click', toggleCert);
	$('unrelated').addEventListener('click', toggleCert);

	document.querySelector('.presets').addEventListener('click', (e) => {
		const p = e.target.dataset.preset;
		if (!p) return;
		applyPreset(p);
		const guide = { nginx: 'nginx', apache: 'apache', tomcat: 'tomcat', iis: 'iis', haproxy: 'haproxy' }[p];
		if (guide) { state.guide = guide; renderGuide(); }
	});
	$('formats').addEventListener('change', updateDownloadInfo);
	$('keyFormat').addEventListener('change', updateDownloadInfo);
	$('outPassword').addEventListener('input', updateDownloadInfo);
	$('baseName').addEventListener('input', () => { state.baseNameTouched = true; updateFileNames(); });
	$('outAlias').addEventListener('input', () => { state.aliasTouched = true; renderGuide(); });
	$('downloadBtn').addEventListener('click', download);
	$('guideTabs').addEventListener('click', (e) => {
		if (!e.target.dataset.guide) return;
		state.guide = e.target.dataset.guide;
		renderGuide();
	});
}

function toggleCert(e) {
	const head = e.target.closest('[data-toggle]');
	if (!head) return;
	const dl = head.parentElement.querySelector('dl');
	dl.hidden = !dl.hidden;
}

init();
