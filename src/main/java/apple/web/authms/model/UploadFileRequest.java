package apple.web.authms.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UploadFileRequest {
    List<MultipartFile> files;
    List<String> fileIds;
    Optional<List<String>> links;
    List<OrganizationsWithDepartments> contributors;
}