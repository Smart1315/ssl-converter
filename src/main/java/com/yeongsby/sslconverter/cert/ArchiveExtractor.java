package com.yeongsby.sslconverter.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

/**
 * CA 가 보내주는 ZIP 압축파일을 메모리에서 푼다. 디스크에는 아무것도 쓰지 않는다.
 * <p>
 * 압축 폭탄 방지를 위해 파일 수, 파일당 크기, 전체 크기를 제한한다. 한국어 Windows 에서 만든 ZIP 은 파일명이 CP949 이므로 UTF-8 로
 * 읽지 못하면 CP949 로 다시 읽는다.
 */
final class ArchiveExtractor {

	static final int MAX_ENTRIES = 500;

	static final int MAX_ENTRY_BYTES = 5 * 1024 * 1024;

	static final long MAX_TOTAL_BYTES = 50L * 1024 * 1024;

	private static final Charset CP949 = Charset.forName("MS949");

	/** 인증서가 들어 있을 리 없는 문서/이미지/실행 파일은 읽지 않는다 */
	private static final Set<String> SKIPPED_EXTENSIONS = Set.of("pdf", "doc", "docx", "hwp", "hwpx", "xls", "xlsx",
			"ppt", "pptx", "png", "jpg", "jpeg", "gif", "bmp", "html", "htm", "exe", "msi", "dll");

	private ArchiveExtractor() {
	}

	static boolean isZip(byte[] data) {
		return data.length >= 4 && data[0] == 'P' && data[1] == 'K'
				&& ((data[2] == 3 && data[3] == 4) || (data[2] == 5 && data[3] == 6));
	}

	static Extracted extract(byte[] data) {
		try {
			return read(data, StandardCharsets.UTF_8);
		}
		catch (IllegalArgumentException malformedName) {
			return read(data, CP949);
		}
	}

	private static Extracted read(byte[] data, Charset charset) {
		List<InputSource> entries = new ArrayList<>();
		List<String> skipped = new ArrayList<>();
		long total = 0;
		int count = 0;
		try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(data), charset)) {
			ZipEntry entry;
			while ((entry = zip.getNextEntry()) != null) {
				if (++count > MAX_ENTRIES) {
					throw new ConversionException("압축파일 안의 파일이 너무 많습니다 (최대 " + MAX_ENTRIES + "개)");
				}
				String name = entry.getName();
				if (entry.isDirectory() || isSystemFile(name)) {
					continue;
				}
				if (SKIPPED_EXTENSIONS.contains(extension(name))) {
					skipped.add(name);
					continue;
				}
				byte[] bytes = zip.readNBytes(MAX_ENTRY_BYTES + 1);
				if (bytes.length > MAX_ENTRY_BYTES) {
					skipped.add(name + " (크기 초과)");
					continue;
				}
				total += bytes.length;
				if (total > MAX_TOTAL_BYTES) {
					throw new ConversionException("압축 해제 크기가 너무 큽니다 (최대 " + (MAX_TOTAL_BYTES / 1024 / 1024) + "MB)");
				}
				entries.add(new InputSource(name, bytes));
			}
		}
		catch (ZipException ex) {
			String message = String.valueOf(ex.getMessage()).toLowerCase(Locale.ROOT);
			if (message.contains("encrypted")) {
				throw new ConversionException("암호가 걸린 ZIP 파일은 읽을 수 없습니다. 압축을 푼 뒤 안의 파일을 올리세요", ex);
			}
			throw new ConversionException("손상되었거나 지원하지 않는 ZIP 파일입니다: " + ex.getMessage(), ex);
		}
		catch (IOException ex) {
			throw new ConversionException("ZIP 파일을 읽을 수 없습니다: " + ex.getMessage(), ex);
		}
		return new Extracted(entries, skipped);
	}

	private static boolean isSystemFile(String name) {
		String base = name.substring(name.lastIndexOf('/') + 1);
		return name.startsWith("__MACOSX/") || name.contains("/__MACOSX/") || base.startsWith("._")
				|| base.equals(".DS_Store") || base.equalsIgnoreCase("Thumbs.db") || base.equalsIgnoreCase("desktop.ini");
	}

	private static String extension(String name) {
		int dot = name.lastIndexOf('.');
		return (dot < 0 || dot < name.lastIndexOf('/')) ? "" : name.substring(dot + 1).toLowerCase(Locale.ROOT);
	}

	/**
	 * 압축 해제 결과.
	 *
	 * @param entries 검사할 파일
	 * @param skipped 읽지 않은 파일 이름
	 */
	record Extracted(List<InputSource> entries, List<String> skipped) {
	}

}
