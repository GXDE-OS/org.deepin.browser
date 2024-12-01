# ![Logo](chrome/app/theme/chromium/product_logo_64.png) UOS Browser

# 编译方法

## 0.安装依赖包 
(如果之请编译过，已经安装过依赖，这一步跳过)  
cd uos-browser  
sudo apt-get build-dep .

## 1.修改 ~/.bashrc
添加  
export AR=ar  
export NM=nm  
export CC=clang  
export CXX=clang++

## 2.source ~/.bashrc
这一步是把上面设置的环境变量load到当前的终端环境  
(新开终端tab页或者重启之后就不再需要这一步了)

## 3. ./debian/scripts/unbundle

## 4. ./tools/gn/bootstrap/bootstrap.py --skip-generate-buildfiles

## 5. 生成配置，终端输入下面命令
./out/Release/gn gen out/Release --args="clang_use_chrome_plugins=false host_toolchain=\"//build/toolchain/linux/unbundle:default\" custom_toolchain=\"//build/toolchain/linux/unbundle:default\" host_cpu=\"x64\" is_debug=false use_goma=false use_ozone=false use_sysroot=false use_openh264=false use_allocator=\"none\" use_libjpeg_turbo=true use_custom_libcxx=false use_gnome_keyring=false use_unofficial_version_number=false enable_vr=false enable_nacl=false enable_nacl_nonsfi=false enable_swiftshader=true enable_reading_list=false enable_one_click_signin=false enable_iterator_debugging=false enable_hangout_services_extension=false optimize_webui=true closure_compile=false blink_symbol_level=0 treat_warnings_as_errors=false  use_gio=true use_pulseaudio=true link_pulseaudio=true enable_widevine=false v8_enable_backtrace=true use_system_zlib=false use_system_lcms2=false use_system_libjpeg=true use_system_freetype=true use_system_harfbuzz=true use_system_libopenjpeg2=true concurrent_links=1 proprietary_codecs=true ffmpeg_branding=\"Chrome\" fieldtrial_testing_like_official_build=true "

## 6. ninja -C out/Release chrome chrome_sandbox
开始编译，大约3个小时左右

## 7. 修改sandbox权限
cd out/Release  
mv chrome_sandbox browser-sandbox  
sudo chown root:root browser-sandbox  
sudo chmod 4755 browser-sandbox  

## 8. 运行
./chrome --user-data-dir=/home/xxxxx/xxxxxxx

其中--user-data-dir后面是自己指定的本机一个文件夹，防止跟之前装的chrome用户数据冲突，导致启动不了

# 修改代码后

## ninja -C out/Release chrome  
执行这一句就可以，只编译改动的文件

