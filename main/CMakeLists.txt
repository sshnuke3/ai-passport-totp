idf_component_register(
    SRCS "main.c"
         "demo_navigation.c"
         "ui_pixel.c"
         "ui_pixel_math.c"
         "demo_display.c"
         "demo_button.c"
         "demo_audio.c"
         "demo_battery.c"
         "demo_radio.c"
         "demo_wifi.c"
         "demo_ble.c"
         "demo_low_power.c"
         "totp_model.c"
         "totp_store.c"
         "totp_time.c"
         "totp_portal.c"
         "totp_pin.c"
         "totp_crypto.c"
         "demo_totp.c"
    INCLUDE_DIRS "."
    REQUIRES bsp bt esp_event esp_hw_support esp_netif esp_timer esp_wifi nvs_flash esp_http_server lwip
)

# 字体资产：由 tools/gen_totp_font.py 从设备渲染文案自动抽取生成，勿手改
target_sources(${COMPONENT_LIB} PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../assets/fonts/font_totp_16.c"
    "${CMAKE_CURRENT_LIST_DIR}/../assets/fonts/font_totp_44.c"
)
