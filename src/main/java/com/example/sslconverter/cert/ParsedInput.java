package com.example.sslconverter.cert;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 모든 입력에서 추출한 인증서/개인키 모음. 같은 인증서나 키가 여러 파일에 있어도 한 번만 보관한다.
 */
public class ParsedInput {

	private final Map<String, X509Certificate> certificates = new LinkedHashMap<>();

	private final Map<String, PrivateKey> privateKeys = new LinkedHashMap<>();

	private final List<SourceSummary> sources = new ArrayList<>();

	private final List<KeystoreEntry> keystoreEntries = new ArrayList<>();

	private final List<String> warnings = new ArrayList<>();

	private final List<String> errors = new ArrayList<>();

	private String selectedAlias;

	void addCertificate(X509Certificate certificate) {
		try {
			this.certificates.putIfAbsent(Base64.getEncoder().encodeToString(certificate.getEncoded()), certificate);
		}
		catch (CertificateEncodingException ex) {
			throw new ConversionException("인증서 인코딩 실패: " + ex.getMessage(), ex);
		}
	}

	void addPrivateKey(PrivateKey key) {
		this.privateKeys.putIfAbsent(Base64.getEncoder().encodeToString(key.getEncoded()), key);
	}

	void addSource(SourceSummary summary) {
		this.sources.add(summary);
	}

	void addKeystoreEntry(KeystoreEntry entry) {
		this.keystoreEntries.add(entry);
	}

	void addWarning(String warning) {
		this.warnings.add(warning);
	}

	void addError(String error) {
		this.errors.add(error);
	}

	void setSelectedAlias(String selectedAlias) {
		this.selectedAlias = selectedAlias;
	}

	public List<X509Certificate> certificates() {
		return List.copyOf(this.certificates.values());
	}

	public List<PrivateKey> privateKeys() {
		return List.copyOf(this.privateKeys.values());
	}

	public List<SourceSummary> sources() {
		return this.sources;
	}

	public List<KeystoreEntry> keystoreEntries() {
		return this.keystoreEntries;
	}

	public List<String> warnings() {
		return this.warnings;
	}

	public List<String> errors() {
		return this.errors;
	}

	public String selectedAlias() {
		return this.selectedAlias;
	}

	/**
	 * 입력 하나에서 무엇을 찾았는지에 대한 요약.
	 */
	public record SourceSummary(String name, String format, int certificates, int privateKeys, List<String> notes) {
	}

	/**
	 * 키스토어(PFX/JKS) 안의 별칭 하나.
	 */
	public record KeystoreEntry(String source, String alias, String type) {
	}

}
