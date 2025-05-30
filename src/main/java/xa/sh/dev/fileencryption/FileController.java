package xa.sh.dev.fileencryption;

import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;


@RestController
@RequestMapping("api")
public class FileController {
    @PostMapping("/encrypt")
public ResponseEntity<Resource> encryptFile(@RequestParam("file") MultipartFile file,
                                            @RequestParam("key") String key) throws Exception {
    byte[] encrypted = EncryptionUtil.encrypt(file.getBytes(), key);
    String originalName = file.getOriginalFilename();
    
    // Add timestamp BEFORE .enc

    String base = originalName.contains(".") ? originalName.substring(0, originalName.lastIndexOf('.')) : originalName;
    String extension = originalName.contains(".") ? originalName.substring(originalName.lastIndexOf('.')) : "";
    String fileWithEnc = base + extension + ".enc";

    return prepareFileResponse(encrypted, fileWithEnc);
}

@PostMapping("/decrypt")
public ResponseEntity<Resource> decryptFile(@RequestParam("file") MultipartFile file,
                                            @RequestParam("key") String key) throws Exception {
    try {
            byte[] decrypted = EncryptionUtil.decrypt(file.getBytes(), key);
    String originalName = file.getOriginalFilename();

    if (originalName != null && originalName.endsWith(".enc")) {
        originalName = originalName.substring(0, originalName.length() - 4); // remove .enc
    }

    return prepareFileResponse(decrypted, originalName); // Only one timestamp here

    } catch (Exception e) {

        return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body(new ByteArrayResource(("Wrong key provided or corrupt file.").getBytes()));

    }
}

    private ResponseEntity<Resource> prepareFileResponse(byte[] data, String filename) {
    String finalName = filename;
    
    ByteArrayResource resource = new ByteArrayResource(data);
    return ResponseEntity.ok()
                         .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + finalName + "\"")
                         .contentType(MediaType.APPLICATION_OCTET_STREAM)
                         .body(resource);
}


}
