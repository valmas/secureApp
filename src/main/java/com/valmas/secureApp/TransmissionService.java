package com.rasp.remote;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.*;
import java.nio.charset.StandardCharsets;

@RestController()
public class TransmissionService {

    @GetMapping(path = "/run")
    public void runCmd() {
        System.out.println("Running");
        try {
            Process p = new ProcessBuilder("whoami").start();
            int errCode = p.waitFor();
            System.out.println("Command executed, any errors? " + (errCode == 0 ? "No" : "Yes") + " " + errCode);
            System.out.println(output(p.getInputStream()));
            System.out.println(output(p.getErrorStream()));
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    private static String output(InputStream inputStream) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))) {
            String line = null;
            while ((line = br.readLine()) != null) {
                sb.append(line).append(System.getProperty("line.separator"));
            }
        }
        return sb.toString();
    }
}
