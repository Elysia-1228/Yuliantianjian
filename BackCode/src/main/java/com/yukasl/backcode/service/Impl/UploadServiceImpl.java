package com.yukasl.backcode.service.impl;

import com.yukasl.backcode.config.FileUploadConfig;
import com.yukasl.backcode.exception.BusinessException;
import com.yukasl.backcode.mapper.UploadMapper;
import com.yukasl.backcode.pojo.VO.QueryUploadVO;
import com.yukasl.backcode.pojo.VO.UploadVO;
import com.yukasl.backcode.pojo.entity.networkThreatUpload;
import com.yukasl.backcode.service.UploadService;
import com.yukasl.backcode.utils.FileUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;


@Slf4j
@Service
public class UploadServiceImpl implements UploadService {


    @Autowired
    private FileUploadConfig fileUploadConfig;

    @Autowired
    private UploadMapper uploadMapper;
    @Autowired
    private RestTemplate restTemplate;
    /**
     * 文件上传服务实现类（核心业务逻辑）
     */
    @Override
    public UploadVO uploadSingleFile(MultipartFile file, Integer collectedDataId) {
        UploadVO uploadVO = fileUpload(file, collectedDataId);

        return uploadVO;
    }

    /**
     * 查询数据上报进度
     * @param id
     * @return
     */
    @Override
    public QueryUploadVO queryUpload(Integer id) {
        if (id == null){
            throw new RuntimeException("查询数据上报进度所需的参数Id为空");
        }
        QueryUploadVO queryUploadVO =  uploadMapper.queryById(id);
        return queryUploadVO;
    }


    /**
     * 文件上传业务逻辑
     * @param file
     * @param collectedDataId
     * @return
     */
    private UploadVO fileUpload(MultipartFile file, Integer collectedDataId) {
        // 1. 基础校验
        if (file.isEmpty() || file.getSize() <= 0) {
            throw new BusinessException("上传文件不能为空或大小为0");
        }

        String originalFilename = file.getOriginalFilename();
        String contentType = file.getContentType();
        long fileSize = file.getSize();
        log.info("开始处理文件上传：原始文件名={}, Content-Type={}, 大小={}",
                originalFilename, contentType, FileUtils.bytesToKb(fileSize));

        // 2. 文件类型双重验证
        String fileExtension = FileUtils.getFileExtension(originalFilename);
        if (!fileUploadConfig.getAllowedExtensions().contains(fileExtension)) {
            throw new BusinessException("不支持的文件类型！允许的类型：" +
                    StringUtils.collectionToCommaDelimitedString(fileUploadConfig.getAllowedExtensions()));
        }
        if (!fileUploadConfig.getAllowedContentTypes().contains(contentType)) {
            throw new BusinessException("文件类型不匹配！请上传合法的PDF/CSV/JSON文件");
        }

        // 3. 核心修改：获取项目根目录 + 拼接上传路径（100%可靠）
        String projectRootPath = System.getProperty("user.dir"); // 项目根目录（如：D:\work\file-upload-demo）
        String basePath = fileUploadConfig.getBasePath(); // 配置的相对路径（src/main/resources/upload/）
        String uploadRootPath = projectRootPath + File.separator + basePath; // 拼接后的上传根路径

        // 4. 构建按日期分的子目录
        String dateDir = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String saveDir = uploadRootPath + File.separator + dateDir + File.separator; // 最终保存目录
        String relativePath = dateDir + File.separator; // 相对 resource 的路径（用于下载）

        // 5. 强制创建目录（即使父目录不存在，递归创建）
        File dir = new File(saveDir);
        if (!dir.exists()) {
            // 注意：mkdirs() 是递归创建目录，mkdir() 只能创建单级目录，这里必须用 mkdirs()
            boolean mkdirsSuccess = dir.mkdirs();
            if (!mkdirsSuccess) {
                log.error("创建文件保存目录失败：{}", saveDir);
                throw new BusinessException("服务器存储目录创建失败，请检查目录权限");
            }
            log.info("成功创建目录：{}", saveDir);
        }

        // 6. 生成唯一文件名并保存
        String uniqueFileName = UUID.randomUUID().toString() + "." + fileExtension;
        String saveFilePath = saveDir + uniqueFileName;

        try {
            file.transferTo(new File(saveFilePath));
            log.info("文件上传成功：保存路径={}", saveFilePath);
        } catch (IOException e) {
            log.error("文件保存失败：", e);
            throw new BusinessException("文件上传失败：" + e.getMessage());
        }

/*        // 7. 封装返回结果
        FileUploadVO fileUploadVO = new FileUploadVO();
        fileUploadVO.setOriginalFileName(originalFilename);
        fileUploadVO.setUniqueFileName(uniqueFileName);
        fileUploadVO.setSaveFilePath(saveFilePath);
        fileUploadVO.setRelativePath(relativePath + uniqueFileName); // 相对 resource 的路径
        fileUploadVO.setFileSize(FileUtils.bytesToKb(fileSize));*/
        networkThreatUpload upload = new networkThreatUpload();
        upload.setUploadResult(1);
        upload.setUploadProgress(100);
        upload.setReportFile(saveFilePath);
        upload.setCreateTime(LocalDateTime.now());
        upload.setUpdateTime(LocalDateTime.now());
        upload.setCollectedDataId(collectedDataId);
        uploadMapper.Insert(upload);
        restTemplate.postForObject("http://localhost:8080/api/chain/alert", upload, String.class);
        UploadVO uploadVO = new UploadVO();
        BeanUtils.copyProperties(upload,uploadVO);

        return uploadVO;
    }
}
