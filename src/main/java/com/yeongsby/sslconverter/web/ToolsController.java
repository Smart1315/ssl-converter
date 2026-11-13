package com.yeongsby.sslconverter.web;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.yeongsby.sslconverter.cert.InputSource;
import com.yeongsby.sslconverter.tools.PkiToolsService;
import com.yeongsby.sslconverter.tools.ToolResult;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

@RestController
@RequestMapping("/api/tools")
public class ToolsController {

	private final PkiToolsService service;

	public ToolsController(PkiToolsService service) { this.service = service; }

	@PostMapping(path = "/{tool}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ToolResult execute(@PathVariable String tool, HttpServletRequest request) throws IOException {
		Map<String, String> fields = new LinkedHashMap<>();
		request.getParameterMap().forEach((key, values) -> { if (values.length > 0) fields.put(key, values[0]); });
		Map<String, List<InputSource>> uploads = new LinkedHashMap<>();
		if (request instanceof MultipartHttpServletRequest multipart) {
			for (Map.Entry<String, List<MultipartFile>> entry : multipart.getMultiFileMap().entrySet()) {
				List<InputSource> files = new ArrayList<>();
				for (MultipartFile file : entry.getValue()) {
					if (!file.isEmpty()) files.add(new InputSource(file.getOriginalFilename() == null ? "업로드 파일" : file.getOriginalFilename(), file.getBytes()));
				}
				uploads.put(entry.getKey(), files);
			}
		}
		return service.execute(tool, fields, uploads);
	}
}
