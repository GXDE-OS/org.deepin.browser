cr.define('uos_newtab', function() {
  'use strict';

  /**
   * Be polite and insert translated hello world strings for the user on loading.
   
  function initialize() {
    $('welcome-message').textContent = loadTimeData.getStringF('welcomeMessage',
        loadTimeData.getString('userName'));
  }*/
  let searchType = 0,
      engineType = 0,
      rightClickEle = null,
      eventsType = null,
      eventsInfo = {},
      urlVaild = true,
      isAdd= true,
      isbackout= true,
      floatTimer= null,
      searchLink = [
        [
          {"link" : "https://www.baidu.com/s?&ie=utf-8&wd="},
          {"link" : "https://image.baidu.com/search/index?tn=baiduimage&fm=result&ie=utf-8&word="},
          {"link" : "https://www.baidu.com/s?tn=news&word="},
          {"link" : "https://www.baidu.com/sf/vsearch?pd=video&tn=vsearch&ie=utf-8&wd="},
          {"link" : "https://map.baidu.com/search/?querytype=s&da_src=shareurl&wd="}
        ],
        [
          {"link" : "https://www.sogou.com/web?query="},
          {"link" : "https://pic.sogou.com/pics?ie=utf8&query="},
          {"link" : "https://news.sogou.com/news?ie=utf8&query="},
          {"link" : "https://v.sogou.com/v?ie=utf8&query="},
          {"link" : "http://map.sogou.com/#lq="}
        ],
        [
          {"link" : "https://www.so.com/s?ie=utf-8&src=se7_newtab_new&q="},
          {"link" : "https://image.so.com/i?ie=utf-8&src=se7_newtab_new&q="},
          {"link" : "https://news.so.com/ns?src=se7_newtab_new&q="},
          {"link" : "https://video.360kan.com/v?src=se7_newtab_new&q="},
          {"link" : "https://ditu.so.com/?&src=se7_newtab_new&k="}
        ]
        ,
        [
          {"link" : "https://cn.bing.com/search?q="},
          {"link" : "https://cn.bing.com/images/search?tsc=ImageBasicHover&q="},
          {"link" : ""},//无资讯
          {"link" : "https://cn.bing.com/videos/search?q="},
          {"link" : "https://cn.bing.com/maps?q="}
        ],
        [
          {"link" : "https://www.google.com/search?ie=UTF-8&q="},
          {"link" : "https://www.google.com/search?tbm=isch&q="},
          {"link" : "https://www.google.com/search?tbm=nws&q="},
          {"link" : "https://www.google.com/search?tbm=vid&q="},
          {"link" : "https://www.google.com/maps/search/"}
        ],
        [
          {"link": "https://search.yahoo.com/search?p="},
          {"link": "https://images.search.yahoo.com/search/images?p="},
          {"link": "https://news.search.yahoo.com/search?p="},
          {"link": "https://video.search.yahoo.com/search/video?p="},
          {"link": ""}
        ]
      ],
      siteList = [],
      refreshListHistory = [],
      refreshCount = 0;

  function initialize() {
    addEvents();
    getCustomizeUrlItems_demo();

    chrome.send('GetSearchEnginesList', [2, 4]);
    // chrome.send('getShowSite', [2, 4]);
    
    // resizeHtmlFontSize();
    setThemeColor();
  }
  // function getShowSite(param){
  //   console.log(param);
  //   if(param){
  //     $(".home-slider-wrap").css("display","block");
  //   }
  // }    
  function addResult(data) {
    //alert('The result of our C++ arithmetic: 2 + 2 = ' + result);
    console.log(JSON.parse(data));
    let result = JSON.parse(data);
    if(result.defaults && result.defaults.length != 0) {
      for(let i =0;i<result.defaults.length;i++){
        if(result.defaults[i].default){
          engineType = i;
          if(engineType > 5) {engineType =0};
          changeSearch(engineType);
        }
      }
    }else if(result.defaults.length == 0){
      changeSearch(0);
    }
  }

  function addEvents(){
    $(document).on("click", ".search-wrap .head",
		function(e) {
      e.stopPropagation();
      $(".search-type-box").slideToggle();
      $("#contextMenuWrap").hide();
    });
    $(document).on("click", ".search-wrap .search-type-box dl.list-item",
		function(e) {
			e.stopPropagation();
      engineType = parseInt($(this).data("index"));
      let arr = [];
      arr.push(parseInt(engineType));
      changeSearch(engineType);
      chrome.send('setDefaultSearchEngine',arr);
      $(".search-type-box").slideToggle();
      $("#contextMenuWrap").hide();
    });
    $(document).on("keydown", ".search-wrap input.search_value",
		function(e) {
      e.stopPropagation();
			13 == e.keyCode && (e.stopPropagation(), search());
    });
    $(document).on("click", ".search-wrap .search-list li",
		function(e) {
      // e.stopPropagation();
      searchType = $(this).data("index");
      $(this).addClass("active").siblings().removeClass("active");
    });
    $(document).on("click", "div.thumb",
		function(e) {
      // e.stopPropagation();
      if($(this).parent().parent().parent().data().type == "add"){
        showDialog('add');
        $("#contextMenuWrap").hide();
        return false;
      }
      let id = $(this).parent().parent().parent().data().id,
      link = siteList[siteList.findIndex(item=>item.itemID === id)].url;
			window.location.href = fittleLink(link);
    });
    $(document).on("click", "body",
		function(e) {
      e.stopPropagation();
      $("#contextMenuWrap").hide();
      if(!$(".search-type-box").is(":hidden")){
        $(".search-type-box").slideToggle();
      }
    });
    $(document).on("contextmenu", ".showmenu",
		function(e) {
      return false;
    });
    $(document).on('mousedown', '.showmenu', function(e){
      if(e.which != 3){
          return;
      }
      if($("#contextMenuWrap").is(":hidden")){
        rightClickEle = $(this).parent().parent();
        showMenuList(e.clientX,e.clientY);
      }else {
        $("#contextMenuWrap").hide();
      }
    });
    $(document).on('click', '.context-li', function(e){
      console.log(rightClickEle);
      if($(this).data().type == 'edit'){
        showDialog('edit');
      }else {
        isbackout = true;
        let siteInfo = siteList[siteList.findIndex(item=>item.itemID === rightClickEle.data().id)];
        console.log(siteInfo);
        eventsInfo.url = siteInfo.url.toString();
        eventsInfo.title = siteInfo.title.toString();
        eventsInfo.itemID = siteInfo.itemID;
        eventsInfo.index = siteInfo.index;
        eventsInfo.icon = siteInfo.icon;
        removeCustomizeUrlItem_demo(siteInfo);
        eventsType = "del";
      }
    });
    $("#url").blur(function(){
      if($(this).val().trim() != ""){
        validUrl_demo($(this).val());
      }
    });
    $("#url").keyup(function(e){
      $("#url-error").hide();
      $("#url").removeClass("onerror");
      if($(this).val().trim() != ""){
        $(".action-button").removeProp("disabled");
      }else {
        $(".action-button").prop("disabled",true);
      }
      if(e.keyCode == 13){
        validUrl_demo($(this).val());
        if($(this).val().trim() != ""){
          let timer = setTimeout(function(){
            saveLinkInfo();
            clearTimeout(timer);
          },0)          
        }
      }
    });
    $("#name").keyup(function(e){
      $("#name-error").hide();
      $("#name").removeClass("onerror");
      if(e.keyCode == 13){
        if($("#url").val().trim() != ""){
          saveLinkInfo();
        }
      }
    });
    $(".close-icon").click(function(){
      $(".dialog-box ").hide();
    });
    $(".cancel-button").click(function(){
      $(".dialog-box ").hide();
    });
    $(".action-button").click(function(){
      saveLinkInfo();
    });
    window.onresize = function(){
      $("#contextMenuWrap").hide();
    }
    window.addEventListener('keydown', e => {
      if(e.keyCode == 27){
        $(".dialog-box ").hide();
        $("#contextMenuWrap").hide();
      }
    });
    document.querySelector("#url").addEventListener( 'input', () => {
      $("#url-error").hide();
      $("#url").removeClass("onerror");
      if($("#url").val().trim() != ""){
        $(".action-button").removeProp("disabled");
      }else {
        $(".action-button").prop("disabled",true);
      }
    });
    document.querySelector("#name").addEventListener( 'input', () => {
      $("#name-error").hide();
      $("#name").removeClass("onerror");
    });
    // addEventListener( 'input', () => $(IDS.DONE).disabled = ($(IDS.URL_FIELD).value.trim() === ''))

    $(window).off("contextmenu").on("contextmenu",function(){
      $("#contextMenuWrap").hide();
    });
    $(".backout").click(function(){
      backout();
      $(".float-info").fadeOut();
    });
    $(".reset").click(function(){
      restoreCustomizeConfigure_demo();
      $(".float-info").fadeOut();
    });
  }
  function saveLinkInfo(){
    let title = $("#name").val(),
      url = $("#url").val();
      isbackout = true;
      if(title.trim() == ""){
        $("#name-error").show();
        $("#name").addClass("onerror");
        return false;
      }else {
        $("#name-error").hide();
      }
      console.log(urlVaild);
      if(!urlVaild){
        $("#url-error").show();
        $("#url").addClass("onerror");
        return false;
      }else {
        $("#url-error").hide();
      }
      let params = {
        url: url,
        title: title,
        index: ""
      }
      if(isAdd){
        addCurstomizeUrlItems_demo(params);
      }else {
        console.log(siteList);
        let siteInfo = siteList[siteList.findIndex(item=>item.itemID === rightClickEle.data().id)];
        console.log(siteInfo);
        if(siteInfo){
          if(url==siteInfo.url.toString() && title == siteInfo.title.toString()){
            $(".dialog-box ").hide();
            return;
          }
          params.itemID = siteInfo.itemID;
          eventsInfo.url = siteInfo.url.toString();
          eventsInfo.title = siteInfo.title.toString();
          eventsInfo.itemID = siteInfo.itemID;
          eventsInfo.index = siteInfo.index;
          eventsInfo.icon = siteInfo.icon;
          if(siteInfo.icon != "" && url==siteInfo.url.toString()){
            params.icon = siteInfo.icon;
          }
        }else {
          params.itemID = rightClickEle.data().id;
        }
        
        updateCustomizeUrlItem_demo(params);
      }
      $(".dialog-box ").hide();
  }
  function showDialog(type){
    if(type == 'add'){
      isAdd = true;
      $(".title").text(loadTimeData.getString('addLinkTitle'));
      $("#name").val("").removeClass("onerror");
      $("#url").val("").removeClass("onerror");
      $("#name-error").hide();
      $("#url-error").hide();
      $(".action-button").prop("disabled",true);
    }else{
      isAdd = false;
      let siteInfo = siteList[siteList.findIndex(item=>item.itemID === rightClickEle.data().id)];
      $(".title").text(loadTimeData.getString('editLinkTitle'));
      $("#name").val(siteInfo.title).removeClass("onerror");
      $("#url").val(siteInfo.url).removeClass("onerror");
      $("#name-error").hide();
      $("#url-error").hide();
      $(".action-button").removeProp("disabled");
    }
    $(".dialog-box ").show();
    $("#name").focus();
    $("#name").select();
  }
  function showMenuList(x,y){
    let menuHeight = $("#contextMenuWrap").height(),
        menuWight = $("#contextMenuWrap").width(),
        windowHeight = $(window).height(),
        windowWidth = $(window).width();
    if(windowHeight-y < menuHeight){
      $("#contextMenuWrap").css({
        display: "block",
        left: x + "px",
        bottom: (windowHeight - y) + "px",
        top:"unset"
      })
      if(windowWidth - x < menuWight){
        $("#contextMenuWrap").css({
            display: "block",
            left: "unset",
            bottom: (windowHeight - y) + "px",
            top:"unset",
            right:(windowWidth - x) + "px"
        });
      }
    }else {
      $("#contextMenuWrap").css({
        display: "block",
        left: x + "px",
        bottom: "unset",
        top: y + "px"
      });
      if(windowWidth - x < menuWight){
        $("#contextMenuWrap").css({
            display: "block",
            left: "unset",
            bottom: "unset",
            top: y + "px",
            right:(windowWidth - x) + "px"
        });
      }
    }
  }
  function changeSearch(index){
    switch (index) {
      case 0:
        $(".head img").attr("src","chrome://theme/IDR_ICON_BD");
        break; 
      case 1:
        $(".head img").attr("src","chrome://theme/IDR_ICON_SG");
        break; 
      case 2:
        $(".head img").attr("src","chrome://theme/IDR_ICON_360");
        break; 
      case 3:
        $(".head img").attr("src","chrome://theme/IDR_ICON_BING");
        break;
      case 4:
        $(".head img").attr("src","chrome://theme/IDR_ICON_GOOGLE");
        break;
      case 5:
        $(".head img").attr("src","chrome://theme/IDR_ICON_YAHOO");
        break;
    }
    if(index == 5){
      $(".map").hide();;
    }else {
      $(".map").show();
    }
    if(index == 3){
      $(".news").hide();
    }else {
      $(".news").show();
    }
  }
  function search() {
    if ($(".search-wrap input.search_value").val().trim() == "") return false;
    let searchText = $(".search-wrap input.search_value").val();
    let searchUrl = searchLink[engineType][searchType].link+searchText;
    // if(engineType == 5){
    //   searchUrl = searchLink[engineType][0].link + searchText;
    // }
    searchUrl = searchUrl.replace(/\s/g," ");
    console.log(engineType,searchText,searchType,searchUrl);
    window.location.href = searchUrl;
  }
  function showFloatInfo(type){
    console.log(eventsType);
    if(type){
      $(".backout").show();
      $(".reset").show();
      $(".float-info").removeClass("error-msg");
      switch (eventsType) {
        case "add":
          $(".float-title").text(loadTimeData.getString('linkAddedMsg'));
          break; 
        case "edit":
          $(".float-title").text(loadTimeData.getString('linkEditedMsg'));
          break; 
        case "del":
          $(".float-title").text(loadTimeData.getString('linkRemovedMsg'));
          break;
      }
    }else {
      $(".backout").hide();
      $(".reset").hide();
      $(".float-info").addClass("error-msg");
      switch (eventsType) {
        case "add":
          $(".float-title").text(loadTimeData.getString('linkCantCreate'));
          break; 
        case "edit":
          $(".float-title").text(loadTimeData.getString('linkCantEdit'));
          break; 
      }
    }
    $(".float-info").fadeIn();
    if(floatTimer){
      clearTimeout(floatTimer);
      floatTimer = setTimeout(function(){
        $(".float-info").fadeOut();
        clearTimeout(floatTimer);
      },10000)
    }else {
      floatTimer = setTimeout(function(){
        $(".float-info").fadeOut();
        clearTimeout(floatTimer);
      },10000)
    }
  } 

  function backout(){
    console.log(eventsType,eventsInfo);
    isbackout = false;
    console.log(refreshListHistory);
    switch (eventsType) {
      case "add":
        removeCustomizeUrlItem_demo(eventsInfo);
        break; 
      case "edit":
        let lastList = refreshListHistory[refreshCount-2];
        let siteInfo = lastList[lastList.findIndex(item=>item.itemID === eventsInfo.itemID)];
        console.log(siteInfo)
        if(siteInfo){
          updateCustomizeUrlItem_demo(siteInfo);
        }
        break; 
      case "del":
        if(siteList.length < 12){
          let a = refreshListHistory[refreshCount-2];
          let b = refreshListHistory[refreshCount-1];
          let arr =[];
          if(a.length > b.length){
            arr = [...a].filter(x => [...b].every(y => y.itemID !== x.itemID));
            console.log('arr',arr);
            addCurstomizeUrlItems_demo(arr[0]);
          }
        }
        break;
    }
    eventsType = null;
    refreshListHistory = [];
    refreshCount = 0;
    eventsInfo = {};
  }
  // 数据排序
  function sortId(a,b){  
    return a.index-b.index  
  }
  function fittleLink(link){
    let i = /^([hH][tT]{2}[pP]:|[hH][tT]{2}[pP][sS]:)/;
    if(!i.test(link)){link = "https://"+link;}
    return link;
  }
  // function resizeHtmlFontSize(){
  //   let Htmlele=document.getElementsByTagName("html")[0];
  //   let font =  Htmlele.offsetWidth/1920*100 > 41.6667 ? Htmlele.offsetWidth/1920*100:41.6667
  //   Htmlele.style.fontSize=font+"px";
  // }
  //获取导航网站信息
  function getCustomizeUrlItems_demo() {
    let data_ = {
      "sessionID":"10", //必须
    };

    let pyload = JSON.stringify(data_);
    chrome.send("getCustomizeUrlItems", [pyload]);
  }
  //导航网站信息列表回调
  function getCustomizeUrlItems_callback(data) {
    let tmp = JSON.parse(data);
    let urlTest = /^([c][h][r][o][m][e][:])/;
    $("#contextMenuWrap").hide();
    if (tmp.result) {
      tmp.result = JSON.parse(tmp.result);
      let homeHtml = "";
      console.log(tmp);
      tmp.result.sort(sortId);
      siteList = tmp.result;
      refreshListHistory.push(siteList);
      refreshCount++;
      tmp.result.forEach((item) => {
        let iconUrl = item.icon;
        let bgUrl = "";
        let iconDiv = "";
        if(item.icon != " " && !urlTest.test(item.url)){
          iconUrl = "data:image/png;base64,"+iconUrl;
          bgUrl = "url("+iconUrl+");"
          iconDiv = '<div class="thumb" style="background-image:url('+iconUrl+');"></div>';
        }else {
          iconDiv = '<div class="thumb" style="background-image:-webkit-image-set(url('+
            'chrome://favicon2/?size=76&scale_factor=1x&show_fallback_monogram=&page_url='+fittleLink(item.url)+') 1x)"></div>';
        }
        homeHtml+='<div class="item drag-item" data-id='+item.itemID+
          ' data-type="edit" draggable="false" >'+
          '<dl class="item-move-hover"><dt class="default showmenu">'+
              iconDiv+
              '<span class="btn-del"></span><span class="btn-edit"></span></dt>'+
            '<dd>'+formatTitle(item.title)+'</dd></dl></div>'
      });
      if(tmp.result.length < 12){
        homeHtml+='<div class="item add" data-type="add" draggable="false">'+
        '<dl class="item-move-hover"><dt class="default">'+
            '<div class="thumb bg76"></div>'+
            '<span class="btn-del"></span><span class="btn-edit"></span></dt>'+
          '<dd>'+loadTimeData.getString('addLinkTitle')+'</dd></dl></div>'
      }
      $(".inner-item").html(homeHtml);
    } else {
      console.log(tmp);
      siteList = [];
    }
    console.log(siteList);
  }
  function formatTitle(title){
    return title.replace(/</g, "&lt;").replace(/>/g, "&gt;")
  }
  //添加自定义链接项
  function addCurstomizeUrlItems_demo(data) {
    console.log(data);
    let icon = " ";
    eventsType = "add";
    if(data.icon){
      icon = data.icon;
    }
    let data_ = {
      "sessionID":"10",         //必须
      "url":data.url, //必须
      "title":data.title,            //必须
      "icon":icon,           //必须
      "index": data.index               //可选
    };
    let pyload = JSON.stringify(data_);
    chrome.send("addCustomizeUrlItems", [pyload]);
  }

  function addCustomizeUriItem_callback(data) {
    data = JSON.parse(data);
    console.log(data);
    if(data.sucess){
      eventsInfo.itemID = data.itemID;
      getCustomizeUrlItems_demo();
      if(isbackout){
        showFloatInfo(true);
      }
    }else {
      showFloatInfo(false);
    }
  }
  //删除自定义链接项
  function removeCustomizeUrlItem_demo(data) {
    let data_ = {
      "sessionID":"10",    //必须
      "itemID":data.itemID,   //必须
    };
    let pyload = JSON.stringify(data_);
    chrome.send("removeCustomizeUrlItems", [pyload]);
  }


  function removeCustomizeUrlItem_callback(data) {
    data = JSON.parse(data);
    console.log(data);
    if(data.sucess){
      getCustomizeUrlItems_demo();
      if(isbackout){
        showFloatInfo(true);
      }
    }
  }
  //更新自定义链接项
  function updateCustomizeUrlItem_demo(data) {
    let icon = " ";
    eventsType = "edit";
    if(data.icon){
      icon = data.icon;
    }
    let data_ = {
      "sessionID":"10",     //必须
      "itemID":data.itemID, //必须
      "icon":icon,
      "title":data.title,
      "url":data.url
    };
    let pyload = JSON.stringify(data_);
    chrome.send("updateCustomizeUrlItems", [pyload]); 
  }

  
  function updateCustomizeUrlItem_callback(data) {
    data = JSON.parse(data);
    console.log(data);
    if(data.sucess){
      getCustomizeUrlItems_demo();
      if(isbackout){
        showFloatInfo(true);
      }
    }else {
      showFloatInfo(false);
    }
  }
  //恢复自定义链接项 
  function restoreCustomizeConfigure_demo() {
    let data_ = {
      "sessionID":"10",   //必须
    };

    let pyload = JSON.stringify(data_);
    chrome.send("restoreCustomizeConfigure", [pyload]);
  }

  function restoreCustomizeConfigure_callback(data) {
    console.log(data);
    getCustomizeUrlItems_demo();
  }
  // 校验网址
  function validUrl_demo(url) {
    let data_ = {
      "sessionID":"10",     //必须
      "url":url
    };

    let pyload = JSON.stringify(data_);
    chrome.send("validUrl", [pyload]);
  }
  
  function validUrl_callback(data) {
    data = JSON.parse(data);
    console.log(data);
    if(data.sucess){
      urlVaild = data.valid;
    }
  }
  function onCustomizeUrlItemsChange(data){
    console.log(data);
    getCustomizeUrlItems_demo();
  }
  // Return an object with all of the exports.
  return {
    addResult: addResult,
    initialize: initialize,
    // getShowSite: getShowSite,
    getCustomizeUrlItems_demo: getCustomizeUrlItems_demo,
    getCustomizeUrlItems_callback: getCustomizeUrlItems_callback,
    addCurstomizeUrlItems_demo: addCurstomizeUrlItems_demo,
    addCustomizeUriItem_callback: addCustomizeUriItem_callback,
    removeCustomizeUrlItem_demo: removeCustomizeUrlItem_demo,
    removeCustomizeUrlItem_callback: removeCustomizeUrlItem_callback,
    updateCustomizeUrlItem_demo: updateCustomizeUrlItem_demo,
    updateCustomizeUrlItem_callback: updateCustomizeUrlItem_callback,
    restoreCustomizeConfigure_demo: restoreCustomizeConfigure_demo,
    restoreCustomizeConfigure_callback: restoreCustomizeConfigure_callback,
    validUrl_demo: validUrl_demo,
    validUrl_callback: validUrl_callback,
    onCustomizeUrlItemsChange: onCustomizeUrlItemsChange
  };
});

document.addEventListener('DOMContentLoaded', uos_newtab.initialize);