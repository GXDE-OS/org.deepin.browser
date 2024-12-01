!function(c) {
	function f(n) {
		if (Array.isArray(n)) {
			var t = c("<ul />").addClass("list");
			for (var a in n) {
				var e = c("<input type='button' />");
				for (var i in n[a]) e.data(i, n[a][i]);
				e.addClass("context-li");
				if (n[a].disabled) e.addClass("disabled-li");
				e.attr("disabled", n[a].disabled);
				e.val(n[a].name),
				t.append(e)
			}
			return t
		}
		return ""
	}
	var p = 0;
	c.fn.contextMenu = function(n, t, a, e) {
		if (void 0 === c(this).get(0)) return this;
		Array.isArray(t) || (t = []),
		this.callback = "function" != typeof e ?
		function() {}: e,
		n.preventDefault(),
		n = n || event;
		o = c("#contextMenuWrap"),
		d = this;
		if (void 0 === o.get(0)) {
			var l = c("<div />").addClass("context-menu-wrap").attr("id", "contextMenuWrap");
			o = c(l),
			c("body").append(o)
		}
		for (var s in o.html(""), t) o.append(f(t[s]));
        //在上面
        if($('.note-editing-area').length<1){ //显示页面单独处理
            if(($(window).height() - n.clientY < o.height()) || (($(window).height() - n.clientY- o.height())<55 && $('.note-editing-area').length<1)){
                o.css({
                    display: "block",
                    left: n.clientX + "px",
                    bottom: ($(window).height() - n.clientY)<55?55:($(window).height() - n.clientY) + "px",
                    top:"unset"
                });
                if($(window).width() - n.clientX < o.width()){
                    o.css({
                        display: "block",
                        left: "unset",
                        bottom: ($(window).height() - n.clientY)<55?55:($(window).height() - n.clientY) + "px",
                        top:"unset",
                        right:($(window).width() - n.clientX) + "px"
                    });
                }
            }else {
                //在下面
                o.css({
                    display: "block",
                    left: n.clientX + "px",
                    top: n.clientY>($(window).height() -55)?($(window).height() -55): n.clientY + "px",
                    bottom: "unset"
                });
                if($(window).width() - n.clientX < o.width()){
                    o.css({
                        display: "block",
                        left: "unset",
                        top: n.clientY>($(window).height() -55)?($(window).height() -55): n.clientY + "px",
                        bottom: "unset",
                        right:($(window).width() - n.clientX) + "px"
                    });
                }
            }
        }else{
            if($(window).height() - n.clientY < o.height()){
                o.css({
                    display: "block",
                    left: n.clientX + "px",
                    bottom: ($(window).height() - n.clientY) + "px",
                    top:"unset"
                });
                if($(window).width() - n.clientX < o.width()){
                    o.css({
                        display: "block",
                        left: "unset",
                        bottom: ($(window).height() - n.clientY) + "px",
                        top:"unset",
                        right:($(window).width() - n.clientX) + "px"
                    });
                }
            }else {
                o.css({
                    display: "block",
                    left: n.clientX + "px",
                    top: n.clientY + "px",
                    bottom: "unset"
                });
                if($(window).width() - n.clientX < o.width()){
                    o.css({
                        display: "block",
                        left: "unset",
                        top: n.clientY + "px",
                        bottom: "unset",
                        right:($(window).width() - n.clientX) + "px"
                    });
                }
            }
        }

		o.find("ul.list input").off("contextmenu").on("contextmenu",
		function(n) {
			n.preventDefault()
		}).off("click").on("click",
		function(e) {
			o.hide(),
			p = 0,
			e.stopPropagation(),
			d.callback(c(this).data(), a)
		});
		var r = !(this.hideContextMenu = function() {
			p = 0,
			o.hide()
		});
		return o.hover(function() {
			r = !0
		},
		function() {
			r = !1
		}),
		c(window).off("click").on("click",
		function() {
			r || o.is(":hidden") || o.hide()
		}),
		c(window).off("contextmenu").on("contextmenu",
		function() {
			0 < p && o && !o.is(":hidden") && !r ? (o.hide(), p = 0) : p++
		}),
		this
	}
} (jQuery);
