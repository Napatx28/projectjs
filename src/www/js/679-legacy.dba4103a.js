"use strict";(self["webpackChunkfrontend"]=self["webpackChunkfrontend"]||[]).push([[679],{45679:function(e,t,r){r.r(t),r.d(t,{default:function(){return C}});var s=function(){var e=this,t=e.$createElement,r=e._self._c||t;return r("v-form",{model:{value:e.valid,callback:function(t){e.valid=t},expression:"valid"}},[r("v-row",[r("v-col",{staticClass:"text-center",attrs:{cols:"12"}},[r("v-img",{staticClass:"mx-auto round-img",attrs:{src:e.pictureUrl,"max-width":"500"}})],1),r("v-col",{staticClass:"pt-3 pb-0",attrs:{cols:"12"}},[r("v-text-field",{attrs:{outlined:"",label:"คำนำหน้าชื่อ",rules:e.rules.prefix},model:{value:e.form.prefix,callback:function(t){e.$set(e.form,"prefix",t)},expression:"form.prefix"}})],1),r("v-col",{staticClass:"py-0",attrs:{cols:"12"}},[r("v-text-field",{attrs:{outlined:"",label:"ชื่อ",rules:e.rules.first_name},model:{value:e.form.first_name,callback:function(t){e.$set(e.form,"first_name",t)},expression:"form.first_name"}})],1),r("v-col",{staticClass:"py-0",attrs:{cols:"12"}},[r("v-text-field",{attrs:{outlined:"",label:"นามสกุล",rules:e.rules.last_name},model:{value:e.form.last_name,callback:function(t){e.$set(e.form,"last_name",t)},expression:"form.last_name"}})],1),r("v-col",{staticClass:"py-0",attrs:{cols:"12"}},[r("v-text-field",{attrs:{outlined:"",label:"รหัสนักศึกษา",rules:e.rules._id},model:{value:e.form._id,callback:function(t){e.$set(e.form,"_id",t)},expression:"form._id"}})],1),r("v-col",{staticClass:"py-0",attrs:{cols:"12"}},[r("v-text-field",{attrs:{outlined:"",label:"คณะ",rules:e.rules.faculty},model:{value:e.form.faculty,callback:function(t){e.$set(e.form,"faculty",t)},expression:"form.faculty"}})],1),r("v-col",{staticClass:"py-0",attrs:{cols:"12"}},[r("v-text-field",{attrs:{outlined:"",label:"ภาควิชา",rules:e.rules.department},model:{value:e.form.department,callback:function(t){e.$set(e.form,"department",t)},expression:"form.department"}})],1),r("v-col",{staticClass:"py-0",attrs:{cols:"12"}},[r("v-select",{attrs:{outlined:"",items:["ชาย","หญิง"],label:"เพศ"},model:{value:e.form.gender,callback:function(t){e.$set(e.form,"gender",t)},expression:"form.gender"}})],1),r("v-col",{staticClass:"py-0",attrs:{cols:"12"}},[r("v-textarea",{attrs:{outlined:"",label:"ที่อยู่",rules:e.rules.address},model:{value:e.form.address,callback:function(t){e.$set(e.form,"address",t)},expression:"form.address"}})],1),r("v-col",{staticClass:"py-0",attrs:{cols:"12"}},[r("v-text-field",{attrs:{outlined:"",label:"ชื่อผู้ใช้",rules:e.rules.username},model:{value:e.form.username,callback:function(t){e.$set(e.form,"username",t)},expression:"form.username"}})],1),r("v-col",{staticClass:"py-0",attrs:{cols:"12"}},[r("v-text-field",{attrs:{outlined:"",type:"password",label:"รหัสผ่าน"},model:{value:e.form.password,callback:function(t){e.$set(e.form,"password",t)},expression:"form.password"}})],1),r("v-col",{staticClass:"py-0",attrs:{cols:"12"}},[r("v-text-field",{attrs:{outlined:"",label:"ยืนยันรหัสผ่าน",rules:e.rules.confirmPassword},model:{value:e.form.confirmPassword,callback:function(t){e.$set(e.form,"confirmPassword",t)},expression:"form.confirmPassword"}})],1),r("v-col",{staticClass:"py-0",attrs:{cols:"12"}},[r("v-text-field",{attrs:{outlined:"",label:"อีเมล์",rules:e.rules.email},model:{value:e.form.email,callback:function(t){e.$set(e.form,"email",t)},expression:"form.email"}})],1),r("v-col",{staticClass:"py-0",attrs:{cols:"12"}},[r("v-text-field",{attrs:{outlined:"",label:"เบอร์โทรศํพท์"},model:{value:e.form.tel,callback:function(t){e.$set(e.form,"tel",t)},expression:"form.tel"}})],1),e.error?r("v-col",{attrs:{cols:"12"}},[r("v-alert",{attrs:{type:"error"}},[e._v(" "+e._s(e.error)+" ")])],1):e._e(),e.success?r("v-col",{attrs:{cols:"12"}},[r("v-alert",{attrs:{type:"success"}},[e._v(e._s(e.success))])],1):e._e(),r("v-col",{staticClass:"text-right",attrs:{cols:"12"}},[r("v-btn",{attrs:{color:"primary",disabled:!e.valid},on:{click:e.edit}},[e._v(" ยืนยัน ")])],1)],1)],1)},l=[],a=(r(99612),r(6241),r(51676)),n=void 0,o=function(e,t,r){return new Promise((function(s,l){var a=function(e){try{o(r.next(e))}catch(t){l(t)}},n=function(e){try{o(r.throw(e))}catch(t){l(t)}},o=function(e){return e.done?s(e.value):Promise.resolve(e.value).then(a,n)};o((r=r.apply(e,t)).next())}))},c={data:function(){return{form:{},valid:!0,error:null,success:null,rules:{prefix:[function(e){return!!e||"กรุณากรอกคำนำหน้าชื่อ"}],first_name:[function(e){return!!e||"กรุณากรอกชื่อ"}],last_name:[function(e){return!!e||"กรุณากรอกนามสกุล"}],_id:[function(e){return!!e||"กรุณากรอกรหัสนักศึกษา"}],faculty:[function(e){return!!e||"กรุณากรอกคณะ"}],department:[function(e){return!!e||"กรุณากรอกภาควิชา"}],gender:[function(e){return!!e||"กรุณาเลือกเพศ"}],address:[function(e){return!!e||"กรุณากรอกที่อยู่"}],username:[function(e){return!!e||"กรุณากรอกชื่อผู้ใช้"}],confirmPassword:[function(e){return e===n.form.password||"รหัสผ่านไม่ตรงกัน"}],email:[function(e){return!!e||"กรุณากรอกอีเมล์"}],tel:[function(e){return!!e||"กรุณากรอกเบอร์โทรศัพท์"}]}}},methods:{edit:function(){return o(this,null,regeneratorRuntime.mark((function e(){var t=this;return regeneratorRuntime.wrap((function(e){while(1)switch(e.prev=e.next){case 0:return e.next=2,a.C.getInstance().put("/user",this.form).then((function(){t.success="อัพเดทสำเร็จ"})).catch((function(e){t.error=e}));case 2:case"end":return e.stop()}}),e,this)})))}},computed:{pictureUrl:function(){return this.$store.getters["me/GET_PICTURE_URL"]}},created:function(){return o(this,null,regeneratorRuntime.mark((function e(){var t;return regeneratorRuntime.wrap((function(e){while(1)switch(e.prev=e.next){case 0:return e.next=2,this.$store.dispatch("me/fetchProfile");case 2:t=e.sent,delete t.password,this.form=null!=t?t:{};case 5:case"end":return e.stop()}}),e,this)})))}},i=c,u=r(1001),f=r(43453),m=r.n(f),d=r(73007),v=r(69856),p=r(38154),x=r(60470),b=r(6134),h=r(87714),_=r(35615),w=r(58488),y=r(94260),k=(0,u.Z)(i,s,l,!1,null,"dda36aa6",null),C=k.exports;m()(k,{VAlert:d.Z,VBtn:v.Z,VCol:p.Z,VForm:x.Z,VImg:b.Z,VRow:h.Z,VSelect:_.Z,VTextField:w.Z,VTextarea:y.Z})}}]);
//# sourceMappingURL=679-legacy.dba4103a.js.map