package com.yeongsby.sslconverter.tools;

import java.util.List;

public record ToolResult(List<String> messages, List<Section> sections, List<Artifact> files, TreeNode tree) {
	public ToolResult {
		messages = messages == null ? List.of() : List.copyOf(messages);
		sections = sections == null ? List.of() : List.copyOf(sections);
		files = files == null ? List.of() : List.copyOf(files);
	}

	public record Section(String title, String level, List<Row> rows) {
		public Section {
			rows = rows == null ? List.of() : List.copyOf(rows);
		}
	}

	public record Row(String label, String value) {
	}

	public record Artifact(String name, String content) {
	}

	public record TreeNode(String name, String value, List<TreeNode> children) {
		public TreeNode {
			children = children == null ? List.of() : List.copyOf(children);
		}
	}
}
