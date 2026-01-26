package com.yukasl.backcode.mapper;

import com.yukasl.backcode.pojo.DTO.ReportShareDTO;
import com.yukasl.backcode.pojo.entity.reportShare;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Update;

import java.util.List;

@Mapper
public interface ReportShareMapper {
    List<reportShare> queryReportShare(ReportShareDTO reportShareDTO);

    @Insert("insert into report_share (report_id, shared_org_id, share_time, share_status) VALUES (#{reportId}, #{sharedOrgId}, #{shareTime}, #{shareStatus})")
    void insertReportShare(ReportShareDTO reportShareDTO);

    @Update("update report_share set share_status = #{reportShareDTO.shareStatus}, share_time = #{reportShareDTO.shareTime} where id = #{id}")
    void updateReportShare(String id, ReportShareDTO reportShareDTO);

    @org.apache.ibatis.annotations.Delete("delete from report_share where shared_org_id = #{sharedOrgId}")
    void deleteBySharedOrgId(String sharedOrgId);

    reportShare queryLatestReportShare();
}