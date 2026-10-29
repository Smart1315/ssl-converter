package com.example.sslconverter.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import com.example.sslconverter.cert.ConversionException;
import com.example.sslconverter.cert.ConverterService;
import com.example.sslconverter.cert.ConverterService.Analysis;
import com.example.sslconverter.cert.Exporter.ExportedFile;
import com.example.sslconverter.cert.ExportOptions;
import com.example.sslconverter.cert.InputSource;
import com.example.sslconverter.cert.OutputFormat;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * 웹 화면용 API. 요청마다 파일을 다시 받아 메모리에서만 처리한다 (서버 측 세션/저장 없음).
 */
@RestController
@RequestMapping("/api")
public class ConverterController {

	private final ConverterService service;

	public ConverterController(ConverterService service) {
		this.service = service;
	}

	@PostMapping(path = "/analyze", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public Analysis analyze(@RequestParam(name = "files", required = false) List<MultipartFile> files,
			@RequestParam(name = "text", required = false) String text,
			@RequestParam(name = "password", required = false) String password,
			@RequestParam(name = "alias", required = false) String alias) throws IOException {
		return this.service.analyze(sources(files, text), chars(password), blankToNull(alias));
	}

	@PostMapping(path = "/convert", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<byte[]> convert(@RequestParam(name = "files", required = false) List<MultipartFile> files,
			@RequestParam(name = "text", required = false) String text,
			@RequestParam(name = "password", required = false) String password,
			@RequestParam(name = "alias", required = false) String alias,
			@RequestParam(name = "formats", required = false) List<String> formats,
			@RequestParam(name = "baseName", required = false) String baseName,
			@RequestParam(name = "outAlias", required = false) String outAlias,
			@RequestParam(name = "outPassword", required = false) String outPassword,
			@RequestParam(name = "includeRoot", defaultValue = "true") boolean includeRoot,
			@RequestParam(name = "legacyPfx", defaultValue = "false") boolean legacyPfx,
			@RequestParam(name = "keyFormat", defaultValue = "PKCS8") ExportOptions.KeyFormat keyFormat)
			throws IOException {
		ExportOptions options = new ExportOptions(parseFormats(formats), baseName, outAlias, chars(outPassword),
				includeRoot, legacyPfx, keyFormat);
		ExportedFile file = this.service.convert(sources(files, text), chars(password), blankToNull(alias), options)
			.file();
		return ResponseEntity.ok()
			.header(HttpHeaders.CONTENT_DISPOSITION,
					ContentDisposition.attachment().filename(file.fileName(), StandardCharsets.UTF_8).build().toString())
			.contentType(MediaType.parseMediaType(file.contentType()))
			.body(file.data());
	}

	private static List<InputSource> sources(List<MultipartFile> files, String text) throws IOException {
		List<InputSource> sources = new ArrayList<>();
		if (files != null) {
			for (MultipartFile file : files) {
				if (!file.isEmpty()) {
					String name = (file.getOriginalFilename() != null) ? file.getOriginalFilename() : "업로드 파일";
					sources.add(new InputSource(name, file.getBytes()));
				}
			}
		}
		if (text != null && !text.isBlank()) {
			sources.add(new InputSource("붙여넣은 텍스트", text.getBytes(StandardCharsets.UTF_8)));
		}
		return sources;
	}

	private static Set<OutputFormat> parseFormats(List<String> formats) {
		Set<OutputFormat> result = EnumSet.noneOf(OutputFormat.class);
		if (formats != null) {
			for (String format : formats) {
				try {
					result.add(OutputFormat.valueOf(format.trim()));
				}
				catch (IllegalArgumentException ex) {
					throw new ConversionException("알 수 없는 출력 형식입니다: " + format);
				}
			}
		}
		return result;
	}

	private static char[] chars(String value) {
		return (value == null || value.isEmpty()) ? null : value.toCharArray();
	}

	private static String blankToNull(String value) {
		return (value == null || value.isBlank()) ? null : value.trim();
	}

}
