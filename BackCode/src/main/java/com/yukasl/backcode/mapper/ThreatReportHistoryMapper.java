package com.yukasl.backcode.mapper;

import com.yukasl.backcode.pojo.entity.ThreatReportHistory;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface ThreatReportHistoryMapper {

    @Insert("INSERT INTO threat_report_history (title, report_type, content, create_time) " +
            "VALUES (#{title}, #{reportType}, #{content}, #{createTime})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void insert(ThreatReportHistory history);

    @Select("SELECT * FROM threat_report_history ORDER BY create_time DESC")
    List<ThreatReportHistory> selectAll();

    @org.apache.ibatis.annotations.Update("UPDATE threat_report_history SET title = #{title} WHERE id = #{id}")
    void updateTitle(Integer id, String title);

    @org.apache.ibatis.annotations.Delete("DELETE FROM threat_report_history WHERE id = #{id}")
    void deleteById(Integer id);
}
