package com.yeongsby.sslconverter;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.yeongsby.sslconverter.cert.InputParser;
import com.yeongsby.sslconverter.tools.PkiToolsService;
import com.yeongsby.sslconverter.web.ToolsController;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@SpringBootTest
class SslConverterApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	void csrToolEndpointReturnsGeneratedArtifacts() throws Exception {
		MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new ToolsController(new PkiToolsService(new InputParser()))).build();
		mockMvc.perform(multipart("/api/tools/csr").param("commonName", "api.example.test").param("keyType", "EC"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.files[0].name").value("request.csr"))
			.andExpect(jsonPath("$.files[1].name").value("private-key.pem"));
	}

}
