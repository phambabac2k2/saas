package com.bacpham.saas.services.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class TelegramNotificationService {

    @Value("${app.telegram.bot-token:}")
    private String botToken;

    @Value("${app.telegram.chat-id:}")
    private String chatId;

    @Value("${app.telegram.approval-url:}")
    private String approvalUrl;

    private final RestTemplate restTemplate = new RestTemplate();

    public void sendApprovalNotification(String companyName, String adminEmail, String companyCode) {
        if (botToken == null || botToken.isBlank() || chatId == null || chatId.isBlank()) {
            log.warn("Telegram bot token or chat ID is not configured. Skipping notification.");
            return;
        }

        String url = "https://api.telegram.org/bot" + botToken + "/sendMessage";
        
        String message = String.format(
            "*Yêu Cầu Duyệt Doanh Nghiệp Mới*\n\n" +
            "*Tên công ty:* %s\n" +
            "*Mã công ty:* `%s`\n" +
            "*Email admin:* %s\n\n" +
            "🔗 [Nhấn vào đây để duyệt](%s)} )",
            companyName, companyCode, adminEmail, approvalUrl
        );

        Map<String, Object> request = new HashMap<>();
        request.put("chat_id", chatId);
        request.put("text", message);
        request.put("parse_mode", "Markdown");

        try {
            log.info("Sending registration notification for tenant {} to Telegram...", companyName);
            restTemplate.postForObject(url, request, String.class);
            log.info("Telegram notification sent successfully.");
        } catch (Exception e) {
            log.error("Failed to send Telegram notification for tenant {}: {}", companyName, e.getMessage());
        }
    }
}
