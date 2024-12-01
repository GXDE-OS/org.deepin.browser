#!/bin/sh

export AR=ar  
export NM=nm  
export CC=clang  
export CXX=clang++

./debian/scripts/unbundle

./tools/gn/bootstrap/bootstrap.py --skip-generate-buildfiles

./out/Release/gn gen out/Release --args="clang_use_chrome_plugins=false host_toolchain=\"//build/toolchain/linux/unbundle:default\" custom_toolchain=\"//build/toolchain/linux/unbundle:default\" host_cpu=\"x64\" is_debug=false use_goma=false use_ozone=false use_sysroot=false use_openh264=false use_allocator=\"none\" use_libjpeg_turbo=true use_custom_libcxx=false use_gnome_keyring=false use_unofficial_version_number=false enable_vr=false enable_nacl=false enable_nacl_nonsfi=false enable_swiftshader=false enable_reading_list=false enable_one_click_signin=false enable_iterator_debugging=false enable_hangout_services_extension=false optimize_webui=false closure_compile=false blink_symbol_level=0 treat_warnings_as_errors=false  use_gio=true use_pulseaudio=true link_pulseaudio=true enable_widevine=true v8_enable_backtrace=true use_system_zlib=true use_system_lcms2=false use_system_libjpeg=true use_system_freetype=true use_system_harfbuzz=true use_system_libopenjpeg2=true concurrent_links=1 proprietary_codecs=true ffmpeg_branding=\"Chrome\" fieldtrial_testing_like_official_build=true "

ninja -C out/Release chrome chrome_sandbox


cd out/Release  
mv chrome_sandbox browser-sandbox 
sudo chown root:root browser-sandbox 
sudo chmod 4755 browser-sandbox 
