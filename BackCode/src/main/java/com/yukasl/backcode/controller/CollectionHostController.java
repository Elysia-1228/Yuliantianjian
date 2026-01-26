package com.yukasl.backcode.controller;

import com.yukasl.backcode.pojo.DTO.collectionApiDTO;
import com.yukasl.backcode.pojo.DTO.collectionHostDTO;
import com.yukasl.backcode.pojo.DTO.collectionHostPageDTO;
import com.yukasl.backcode.pojo.entity.networkThreatCollectionApi;
import com.yukasl.backcode.result.PageResult;
import com.yukasl.backcode.result.Result;
import com.yukasl.backcode.service.CollectionHostService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@Slf4j
@RequestMapping("/api/collection")
public class CollectionHostController {
    @Autowired
    private CollectionHostService collectionHostService;

    /**
     * 查询云外主机采集配置列表，支持条件筛选
     *
     * @return
     */
    @GetMapping("/host")
    public Result<PageResult> page(collectionHostPageDTO collectionHostDTO) {
        log.info("查询云外主机采集配置列表,传入的参数为:{}", collectionHostDTO);
        PageResult pageResult = collectionHostService.page(collectionHostDTO);
        return Result.success(pageResult);
    }

    /**
     * 新增主机
     */
    @PostMapping("/host")
    public Result addHost(@RequestBody collectionHostDTO collectionHostDTO) {
        log.info("新增云外主机采集配置,传入的参数为:{}", collectionHostDTO);
        Integer id = collectionHostService.addHost(collectionHostDTO);
        return Result.success(id);
    }

    /**
     * 修改云外主机采集配置
     */
    @PutMapping("/host/{id}")
    public Result UpdateHost(@PathVariable Integer id, @RequestBody collectionHostDTO collectionHostDTO) {
        log.info("修改云外主机采集配置,传入的参数为:id:{},{}", id, collectionHostDTO);
        collectionHostService.updateHost(id, collectionHostDTO);
        return Result.success();
    }

    /**
     * 删除云外主机采集配置
     */
    @DeleteMapping("/host/{id}")
    public Result deleteHost(@PathVariable Integer id) {
        log.info("要删除的主机Id为:{}", id);
        collectionHostService.deleteHost(id);
        return Result.success();
    }

    /**
     * 查询移动云 API 配置详情
     */
    @GetMapping("/api")
    public Result<networkThreatCollectionApi> queryApi(Integer id) {
        log.info("查询移动云 API 配置详情,请求参数Id为->{}", id);
        networkThreatCollectionApi collectionApi = collectionHostService.queryApi(id);
        return Result.success(collectionApi);
    }

    /**
     * 修改移动云 API 配置
     */
    @PutMapping("/api")
    public Result updateApi(@RequestBody collectionApiDTO collectionApiDTO) {
        log.info("修改移动云 API 配置,请求参数collectionApiDTO->{}", collectionApiDTO);
        collectionHostService.updateApi(collectionApiDTO);
        return Result.success();
    }
}