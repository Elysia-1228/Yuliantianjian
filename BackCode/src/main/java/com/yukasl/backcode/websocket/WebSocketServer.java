package com.yukasl.backcode.websocket;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import jakarta.websocket.OnClose;
import jakarta.websocket.OnMessage;
import jakarta.websocket.OnOpen;
import jakarta.websocket.Session;
import jakarta.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * WebSocket 服务端
 */
@Component
@ServerEndpoint("/ids/stream")
@Slf4j
public class WebSocketServer {

    // 存放每个客户端对应的Session对象
    private static CopyOnWriteArraySet<WebSocketServer> webSocketSet = new CopyOnWriteArraySet<>();
    private Session session;

    /**
     * 连接建立成功调用的方法
     */
    @OnOpen
    public void onOpen(Session session) {
        this.session = session;
        webSocketSet.add(this);
        log.info("WebSocket: 新连接加入！当前在线人数: {}", webSocketSet.size());
    }

    /**
     * 连接关闭调用的方法
     */
    @OnClose
    public void onClose() {
        webSocketSet.remove(this);
        log.info("WebSocket: 连接关闭！当前在线人数: {}", webSocketSet.size());
    }

    /**
     * 收到客户端消息后调用的方法
     *
     * @param message 客户端发送过来的消息
     */
    @OnMessage
    public void onMessage(String message, Session session) {
        log.info("WebSocket: 收到来自客户端的消息: {}", message);
        // 这里可以处理客户端的心跳或鉴权消息
    }

    /**
     * 群发自定义消息
     */
    public static void sendInfo(String message) {
        log.info("WebSocket: 推送消息到所有客户端: {}", message);
        for (WebSocketServer item : webSocketSet) {
            try {
                item.session.getBasicRemote().sendText(message);
            } catch (IOException e) {
                log.error("WebSocket: 推送消息失败", e);
            }
        }
    }
}
