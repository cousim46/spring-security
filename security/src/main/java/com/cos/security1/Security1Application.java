package com.cos.security1;

import com.jlefebure.spring.boot.minio.notification.MinioNotification;
import io.minio.MinioClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Security1Application {


    public static void main(String[] args) {
        SpringApplication.run(Security1Application.class, args);
    }

}
