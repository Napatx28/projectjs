"use strict";(self["webpackChunkfrontend"]=self["webpackChunkfrontend"]||[]).push([[17],{66097:function(t,e,n){n.d(e,{Z:function(){return b}});var s=n(60121),i=(n(3794),n(70550),n(58072),n(6241),n(17441),n(39521),n(95103),n(12718),n(40594),n(24226),n(35615)),r=n(58488),a=n(91327),o=n(49132),l=Object.defineProperty,c=Object.defineProperties,u=Object.getOwnPropertyDescriptors,h=Object.getOwnPropertySymbols,d=Object.prototype.hasOwnProperty,f=Object.prototype.propertyIsEnumerable,p=function(t,e,n){return e in t?l(t,e,{enumerable:!0,configurable:!0,writable:!0,value:n}):t[e]=n},m=function(t,e){for(var n in e||(e={}))d.call(e,n)&&p(t,n,e[n]);if(h){var i,r=(0,s.Z)(h(e));try{for(r.s();!(i=r.n()).done;){n=i.value;f.call(e,n)&&p(t,n,e[n])}}catch(a){r.e(a)}finally{r.f()}}return t},v=function(t,e){return c(t,u(e))},I=v(m({},i.l),{offsetY:!0,offsetOverflow:!0,transition:!1}),b=i.Z.extend({name:"v-autocomplete",props:{allowOverflow:{type:Boolean,default:!0},autoSelectFirst:{type:Boolean,default:!1},filter:{type:Function,default:function(t,e,n){return n.toLocaleLowerCase().indexOf(e.toLocaleLowerCase())>-1}},hideNoData:Boolean,menuProps:{type:i.Z.options.props.menuProps.type,default:function(){return I}},noFilter:Boolean,searchInput:{type:String}},data:function(){return{lazySearch:this.searchInput}},computed:{classes:function(){return v(m({},i.Z.options.computed.classes.call(this)),{"v-autocomplete":!0,"v-autocomplete--is-selecting-index":this.selectedIndex>-1})},computedItems:function(){return this.filteredItems},selectedValues:function(){var t=this;return this.selectedItems.map((function(e){return t.getValue(e)}))},hasDisplayedItems:function(){var t=this;return this.hideSelected?this.filteredItems.some((function(e){return!t.hasItem(e)})):this.filteredItems.length>0},currentRange:function(){return null==this.selectedItem?0:String(this.getText(this.selectedItem)).length},filteredItems:function(){var t=this;return!this.isSearching||this.noFilter||null==this.internalSearch?this.allItems:this.allItems.filter((function(e){var n=(0,o.qF)(e,t.itemText),s=null!=n?String(n):"";return t.filter(e,String(t.internalSearch),s)}))},internalSearch:{get:function(){return this.lazySearch},set:function(t){this.lazySearch!==t&&(this.lazySearch=t,this.$emit("update:search-input",t))}},isAnyValueAllowed:function(){return!1},isDirty:function(){return this.searchIsDirty||this.selectedItems.length>0},isSearching:function(){return this.multiple&&this.searchIsDirty||this.searchIsDirty&&this.internalSearch!==this.getText(this.selectedItem)},menuCanShow:function(){return!!this.isFocused&&(this.hasDisplayedItems||!this.hideNoData)},$_menuProps:function(){var t=i.Z.options.computed.$_menuProps.call(this);return t.contentClass="v-autocomplete__content ".concat(t.contentClass||"").trim(),m(m({},I),t)},searchIsDirty:function(){return null!=this.internalSearch&&""!==this.internalSearch},selectedItem:function(){var t=this;return this.multiple?null:this.selectedItems.find((function(e){return t.valueComparator(t.getValue(e),t.getValue(t.internalValue))}))},listData:function(){var t=i.Z.options.computed.listData.call(this);return t.props=v(m({},t.props),{items:this.virtualizedItems,noFilter:this.noFilter||!this.isSearching||!this.filteredItems.length,searchInput:this.internalSearch}),t}},watch:{filteredItems:"onFilteredItemsChanged",internalValue:"setSearch",isFocused:function(t){t?(document.addEventListener("copy",this.onCopy),this.$refs.input&&this.$refs.input.select()):(document.removeEventListener("copy",this.onCopy),this.blur(),this.updateSelf())},isMenuActive:function(t){!t&&this.hasSlot&&(this.lazySearch=null)},items:function(t,e){e&&e.length||!this.hideNoData||!this.isFocused||this.isMenuActive||!t.length||this.activateMenu()},searchInput:function(t){this.lazySearch=t},internalSearch:"onInternalSearchChanged",itemText:"updateSelf"},created:function(){this.setSearch()},destroyed:function(){document.removeEventListener("copy",this.onCopy)},methods:{onFilteredItemsChanged:function(t,e){var n=this;if(t!==e){if(!this.autoSelectFirst){var s=e[this.$refs.menu.listIndex];s?this.setMenuIndex(t.findIndex((function(t){return t===s}))):this.setMenuIndex(-1),this.$emit("update:list-index",this.$refs.menu.listIndex)}this.$nextTick((function(){n.internalSearch&&(1===t.length||n.autoSelectFirst)&&(n.$refs.menu.getTiles(),n.autoSelectFirst&&t.length&&(n.setMenuIndex(0),n.$emit("update:list-index",n.$refs.menu.listIndex)))}))}},onInternalSearchChanged:function(){this.updateMenuDimensions()},updateMenuDimensions:function(){this.isMenuActive&&this.$refs.menu&&this.$refs.menu.updateDimensions()},changeSelectedIndex:function(t){this.searchIsDirty||(this.multiple&&t===o.Do.left?-1===this.selectedIndex?this.selectedIndex=this.selectedItems.length-1:this.selectedIndex--:this.multiple&&t===o.Do.right?this.selectedIndex>=this.selectedItems.length-1?this.selectedIndex=-1:this.selectedIndex++:t!==o.Do.backspace&&t!==o.Do["delete"]||this.deleteCurrentItem())},deleteCurrentItem:function(){var t=this.selectedIndex,e=this.selectedItems[t];if(this.isInteractive&&!this.getDisabled(e)){var n=this.selectedItems.length-1;if(-1!==this.selectedIndex||0===n){var s=this.selectedItems.length,i=t!==s-1?t:t-1,r=this.selectedItems[i];r?this.selectItem(e):this.setValue(this.multiple?[]:null),this.selectedIndex=i}else this.selectedIndex=n}},clearableCallback:function(){this.internalSearch=null,i.Z.options.methods.clearableCallback.call(this)},genInput:function(){var t=r.Z.options.methods.genInput.call(this);return t.data=(0,a.ZP)(t.data,{attrs:{"aria-activedescendant":(0,o.vO)(this.$refs.menu,"activeTile.id"),autocomplete:(0,o.vO)(t.data,"attrs.autocomplete","off")},domProps:{value:this.internalSearch}}),t},genInputSlot:function(){var t=i.Z.options.methods.genInputSlot.call(this);return t.data.attrs.role="combobox",t},genSelections:function(){return this.hasSlot||this.multiple?i.Z.options.methods.genSelections.call(this):[]},onClick:function(t){this.isInteractive&&(this.selectedIndex>-1?this.selectedIndex=-1:this.onFocus(),this.isAppendInner(t.target)||this.activateMenu())},onInput:function(t){if(!(this.selectedIndex>-1)&&t.target){var e=t.target,n=e.value;e.value&&this.activateMenu(),this.multiple||""!==n||this.deleteCurrentItem(),this.internalSearch=n,this.badInput=e.validity&&e.validity.badInput}},onKeyDown:function(t){var e=t.keyCode;!t.ctrlKey&&[o.Do.home,o.Do.end].includes(e)||i.Z.options.methods.onKeyDown.call(this,t),this.changeSelectedIndex(e)},onSpaceDown:function(t){},onTabDown:function(t){i.Z.options.methods.onTabDown.call(this,t),this.updateSelf()},onUpDown:function(t){t.preventDefault(),this.activateMenu()},selectItem:function(t){i.Z.options.methods.selectItem.call(this,t),this.setSearch()},setSelectedItems:function(){i.Z.options.methods.setSelectedItems.call(this),this.isFocused||this.setSearch()},setSearch:function(){var t=this;this.$nextTick((function(){t.multiple&&t.internalSearch&&t.isMenuActive||(t.internalSearch=!t.selectedItems.length||t.multiple||t.hasSlot?null:t.getText(t.selectedItem))}))},updateSelf:function(){(this.searchIsDirty||this.internalValue)&&(this.multiple||this.valueComparator(this.internalSearch,this.getValue(this.internalValue))||this.setSearch())},hasItem:function(t){return this.selectedValues.indexOf(this.getValue(t))>-1},onCopy:function(t){var e,n;if(-1!==this.selectedIndex){var s=this.selectedItems[this.selectedIndex],i=this.getText(s);null==(e=t.clipboardData)||e.setData("text/plain",i),null==(n=t.clipboardData)||n.setData("text/vnd.vuetify.autocomplete.item+plain",i),t.preventDefault()}}}})},51017:function(t,e,n){n.r(e),n.d(e,{default:function(){return x}});var s=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("v-form",[n("v-row",[n("v-col",{staticClass:"pt-6 pb-0",attrs:{cols:"12"}},[n("v-autocomplete",{attrs:{items:t.books,"item-text":"title","item-value":"_id",label:"หนังสือ",outlined:""},model:{value:t.book,callback:function(e){t.book=e},expression:"book"}})],1),n("v-col",{staticClass:"pt-0 pb-0",attrs:{cols:"12"}},[n("v-autocomplete",{attrs:{items:t.users,disabled:t.userForm,"item-text":"name","item-value":"_id",label:"ผู้ยืม",outlined:""},model:{value:t.user,callback:function(e){t.user=e},expression:"user"}})],1),n("v-col",{staticClass:"pt-0 pb-0",attrs:{cols:"12"}},[n("v-text-field",{attrs:{outlined:"",label:"วันกำหนดคืน",disabled:!0},model:{value:t.endDateStr,callback:function(e){t.endDateStr=e},expression:"endDateStr"}})],1),t.error?n("v-col",{staticClass:"pt-0 pb-0",attrs:{cols:"12"}},[n("v-alert",{attrs:{type:"error"}},[t._v(t._s(t.error))])],1):t._e(),n("v-col",{staticClass:"pt-0 pb-0 text-right",attrs:{cols:"12"}},[n("v-btn",{attrs:{color:"primary"},on:{click:t.borrow}},[t._v(" สร้างรายการ ")])],1)],1)],1)},i=[],r=(n(99612),n(6241),n(58072),n(51596),n(23294),n(46393)),a=n.n(r),o=function(t,e,n){return new Promise((function(s,i){var r=function(t){try{o(n.next(t))}catch(e){i(e)}},a=function(t){try{o(n.throw(t))}catch(e){i(e)}},o=function(t){return t.done?s(t.value):Promise.resolve(t.value).then(r,a)};o((n=n.apply(t,e)).next())}))},l={data:function(){return{book:null,user:null,endDate:null,error:null,userForm:!0}},watch:{book:function(t){this.userForm=!t},user:function(){this.getEndDate()}},computed:{books:function(){var t=this.$store.state.book.books.map((function(t){return t.title="".concat(t.title," (").concat(t._id,")"),t}));return t},users:function(){return this.$store.state.user.users.map((function(t){return t.name="".concat(t.first_name," ").concat(t.last_name),t}))},endDateStr:{get:function(){return this.endDate?a()(this.endDate).format("YYYY-MM-DD"):null},set:function(t){this.endDate=new Date(t)}}},created:function(){return o(this,null,regeneratorRuntime.mark((function t(){return regeneratorRuntime.wrap((function(t){while(1)switch(t.prev=t.next){case 0:return t.next=2,this.$store.dispatch("book/fetchAvaliableBooks");case 2:return t.next=4,this.$store.dispatch("user/fetchUsers");case 4:case"end":return t.stop()}}),t,this)})))},methods:{borrow:function(){return o(this,null,regeneratorRuntime.mark((function t(){var e,n,s,i=this;return regeneratorRuntime.wrap((function(t){while(1)switch(t.prev=t.next){case 0:return e=this.book,n=this.user,s={book:e,user:n,endDate:this.endDate},t.next=4,this.$store.dispatch("transaction/borrow",s).then((function(){return i.$router.push("/history-transaction")})).catch((function(t){i.error=t}));case 4:case"end":return t.stop()}}),t,this)})))},getEndDate:function(){return o(this,null,regeneratorRuntime.mark((function t(){var e,n,s,i;return regeneratorRuntime.wrap((function(t){while(1)switch(t.prev=t.next){case 0:return t.next=2,this.$store.dispatch("user/fetchUser",this.user);case 2:return e=t.sent,n=e.job,t.next=6,this.$store.dispatch("book/fetchBook",this.book);case 6:return s=t.sent,i=s.book_type,t.next=10,this.$store.dispatch("transaction/endDate",{job:n,type:i});case 10:this.endDate=t.sent;case 11:case"end":return t.stop()}}),t,this)})))}}},c=l,u=n(1001),h=n(43453),d=n.n(h),f=n(73007),p=n(66097),m=n(69856),v=n(38154),I=n(60470),b=n(87714),g=n(58488),S=(0,u.Z)(c,s,i,!1,null,null,null),x=S.exports;d()(S,{VAlert:f.Z,VAutocomplete:p.Z,VBtn:m.Z,VCol:v.Z,VForm:I.Z,VRow:b.Z,VTextField:g.Z})}}]);
//# sourceMappingURL=17-legacy.021d7a4d.js.map