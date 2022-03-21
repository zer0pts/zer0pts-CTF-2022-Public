"use strict";(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[557],{6729:function(e,t,r){r.d(t,{NJ:function(){return v},NI:function(){return p}});var s=r(4577),n=r(7243),i=r(63),a=r(4915),o=r(5284),l=r(9676),u=r(3105),c=r(4461),d=r(3808),f=r(8500),y=r(2947),b=r(7294);function m(){return(m=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var r=arguments[t];for(var s in r)Object.prototype.hasOwnProperty.call(r,s)&&(e[s]=r[s])}return e}).apply(this,arguments)}function g(e,t){if(null==e)return{};var r,s,n={},i=Object.keys(e);for(s=0;s<i.length;s++)r=i[s],t.indexOf(r)>=0||(n[r]=e[r]);return n}var[h,v]=(0,f.k)({strict:!1,name:"FormControlContext"});var p=(0,i.G)(((e,t)=>{var r=(0,a.j)("Form",e),i=function(e){var{id:t,isRequired:r,isInvalid:i,isDisabled:a,isReadOnly:o}=e,l=g(e,["id","isRequired","isInvalid","isDisabled","isReadOnly"]),u=(0,s.Me)(),d=t||"field-"+u,f=d+"-label",h=d+"-feedback",v=d+"-helptext",[p,O]=b.useState(!1),[_,w]=b.useState(!1),[j,F]=(0,n.k)(),x=b.useCallback((function(e,t){return void 0===e&&(e={}),void 0===t&&(t=null),m({id:v},e,{ref:(0,y.l)(t,(e=>{e&&w(!0)}))})}),[v]),k=b.useCallback((function(e,t){var r,s;return void 0===e&&(e={}),void 0===t&&(t=null),m({},e,{ref:t,"data-focus":(0,c.PB)(j),"data-disabled":(0,c.PB)(a),"data-invalid":(0,c.PB)(i),"data-readonly":(0,c.PB)(o),id:null!=(r=e.id)?r:f,htmlFor:null!=(s=e.htmlFor)?s:d})}),[d,a,j,i,o,f]),V=b.useCallback((function(e,t){return void 0===e&&(e={}),void 0===t&&(t=null),m({id:h},e,{ref:(0,y.l)(t,(e=>{e&&O(!0)})),"aria-live":"polite"})}),[h]),A=b.useCallback((function(e,t){return void 0===e&&(e={}),void 0===t&&(t=null),m({},e,l,{ref:t,role:"group"})}),[l]),S=b.useCallback((function(e,t){return void 0===e&&(e={}),void 0===t&&(t=null),m({},e,{ref:t,role:"presentation","aria-hidden":!0,children:e.children||"*"})}),[]);return{isRequired:!!r,isInvalid:!!i,isReadOnly:!!o,isDisabled:!!a,isFocused:!!j,onFocus:F.on,onBlur:F.off,hasFeedbackText:p,setHasFeedbackText:O,hasHelpText:_,setHasHelpText:w,id:d,labelId:f,feedbackId:h,helpTextId:v,htmlProps:l,getHelpTextProps:x,getErrorMessageProps:V,getRootProps:A,getLabelProps:k,getRequiredIndicatorProps:S}}((0,o.Lr)(e)),{getRootProps:d}=i,f=g(i,["getRootProps","htmlProps"]),v=(0,c.cx)("chakra-form-control",e.className),p=b.useMemo((()=>f),[f]);return b.createElement(h,{value:p},b.createElement(l.Fo,{value:r},b.createElement(u.m$.div,m({},d({},t),{className:v,__css:r.container}))))}));d.Ts&&(p.displayName="FormControl");var O=(0,i.G)(((e,t)=>{var r=v(),s=(0,l.yK)(),n=(0,c.cx)("chakra-form__helper-text",e.className);return b.createElement(u.m$.div,m({},null==r?void 0:r.getHelpTextProps(e,t),{__css:s.helperText,className:n}))}));d.Ts&&(O.displayName="FormHelperText")},2202:function(e,t,r){r.d(t,{Y:function(){return l}});var s=r(4461),n=r(658),i=r(6729);function a(){return(a=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var r=arguments[t];for(var s in r)Object.prototype.hasOwnProperty.call(r,s)&&(e[s]=r[s])}return e}).apply(this,arguments)}function o(e,t){if(null==e)return{};var r,s,n={},i=Object.keys(e);for(s=0;s<i.length;s++)r=i[s],t.indexOf(r)>=0||(n[r]=e[r]);return n}function l(e){var t=function(e){var t,r,s,l=(0,i.NJ)(),{id:u,disabled:c,readOnly:d,required:f,isRequired:y,isInvalid:b,isReadOnly:m,isDisabled:g,onFocus:h,onBlur:v}=e,p=o(e,["id","disabled","readOnly","required","isRequired","isInvalid","isReadOnly","isDisabled","onFocus","onBlur"]),O=e["aria-describedby"]?[e["aria-describedby"]]:[];null!=l&&l.hasFeedbackText&&null!=l&&l.isInvalid&&O.push(l.feedbackId);null!=l&&l.hasHelpText&&O.push(l.helpTextId);return a({},p,{"aria-describedby":O.join(" ")||void 0,id:null!=u?u:null==l?void 0:l.id,isDisabled:null!=(t=null!=c?c:g)?t:null==l?void 0:l.isDisabled,isReadOnly:null!=(r=null!=d?d:m)?r:null==l?void 0:l.isReadOnly,isRequired:null!=(s=null!=f?f:y)?s:null==l?void 0:l.isRequired,isInvalid:null!=b?b:null==l?void 0:l.isInvalid,onFocus:(0,n.v0)(null==l?void 0:l.onFocus,h),onBlur:(0,n.v0)(null==l?void 0:l.onBlur,v)})}(e),{isDisabled:r,isInvalid:l,isReadOnly:u,isRequired:c}=t;return a({},o(t,["isDisabled","isInvalid","isReadOnly","isRequired"]),{disabled:r,readOnly:u,required:c,"aria-invalid":(0,s.Qm)(l),"aria-required":(0,s.Qm)(c),"aria-readonly":(0,s.Qm)(u)})}},9887:function(e,t,r){r.d(t,{I:function(){return f}});var s=r(2202),n=r(63),i=r(4915),a=r(5284),o=r(3105),l=r(4461),u=r(3808),c=r(7294);function d(){return(d=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var r=arguments[t];for(var s in r)Object.prototype.hasOwnProperty.call(r,s)&&(e[s]=r[s])}return e}).apply(this,arguments)}var f=(0,n.G)(((e,t)=>{var r=(0,i.j)("Input",e),n=(0,a.Lr)(e),u=(0,s.Y)(n),f=(0,l.cx)("chakra-input",e.className);return c.createElement(o.m$.input,d({},u,{__css:r.field,ref:t,className:f}))}));u.Ts&&(f.displayName="Input"),f.id="Input"},2283:function(e,t,r){r.d(t,{U2:function(){return y},cI:function(){return je},Gc:function(){return S}});var s=r(7294),n=e=>"checkbox"===e.type,i=e=>e instanceof Date,a=e=>null==e;const o=e=>"object"===typeof e;var l=e=>!a(e)&&!Array.isArray(e)&&o(e)&&!i(e),u=e=>e.substring(0,e.search(/.\d/))||e,c=(e,t)=>[...e].some((e=>u(t)===e)),d=e=>e.filter(Boolean),f=e=>void 0===e,y=(e,t,r)=>{if(l(e)&&t){const s=d(t.split(/[,[\].]+?/)).reduce(((e,t)=>a(e)?e:e[t]),e);return f(s)||s===e?f(e[t])?r:e[t]:s}};const b="blur",m="onBlur",g="onChange",h="onSubmit",v="onTouched",p="all",O="max",_="min",w="maxLength",j="minLength",F="pattern",x="required",k="validate";var V=(e,t)=>{const r=Object.assign({},e);return delete r[t],r};const A=s.createContext(null),S=()=>s.useContext(A);var D=(e,t,r,s=!0)=>{function n(n){return()=>{if(n in e)return t[n]!==p&&(t[n]=!s||p),r&&(r[n]=!0),e[n]}}const i={};for(const a in e)Object.defineProperty(i,a,{get:n(a)});return i},T=e=>l(e)&&!Object.keys(e).length,C=(e,t,r)=>{const s=V(e,"name");return T(s)||Object.keys(s).length>=Object.keys(t).length||Object.keys(s).find((e=>t[e]===(!r||p)))},E=e=>Array.isArray(e)?e:[e];const N=e=>{e.current&&(e.current.unsubscribe(),e.current=void 0)};function R(e){const t=s.useRef(),r=s.useRef((()=>{}));r.current=(({_unsubscribe:e,props:t})=>()=>{t.disabled?N(e):e.current||(e.current=t.subject.subscribe({next:t.callback}))})({_unsubscribe:t,props:e}),!e.skipEarlySubscription&&r.current(),s.useEffect((()=>(r.current(),()=>N(t))),[])}var I=(e,t,r,s,n)=>t?Object.assign(Object.assign({},r[e]),{types:Object.assign(Object.assign({},r[e]&&r[e].types?r[e].types:{}),{[s]:n||!0})}):{},B=e=>/^\w*$/.test(e),q=e=>d(e.replace(/["|']|\]/g,"").split(/\.|\[/));function P(e,t,r){let s=-1;const n=B(t)?[t]:q(t),i=n.length,a=i-1;for(;++s<i;){const t=n[s];let i=r;if(s!==a){const r=e[t];i=l(r)||Array.isArray(r)?r:isNaN(+n[s+1])?{}:[]}e[t]=i,e=e[t]}return e}const M=(e,t,r)=>{for(const s of r||Object.keys(e)){const r=y(e,s);if(r){const e=r._f,s=V(r,"_f");if(e&&t(e.name)){if(e.ref.focus&&f(e.ref.focus()))break;if(e.refs){e.refs[0].focus();break}}else l(s)&&M(s,t)}}};var U=e=>"function"===typeof e;function L(e){let t;const r=Array.isArray(e);if(e instanceof Date)t=new Date(e);else if(e instanceof Set)t=new Set(e);else{if(!r&&!l(e))return e;t=r?[]:{};for(const r in e){if(U(e[r])){t=e;break}t[r]=L(e[r])}}return t}var H=e=>a(e)||!o(e);function $(e,t){if(H(e)||H(t))return e===t;if(i(e)&&i(t))return e.getTime()===t.getTime();const r=Object.keys(e),s=Object.keys(t);if(r.length!==s.length)return!1;for(const n of r){const r=e[n];if(!s.includes(n))return!1;if("ref"!==n){const e=t[n];if(i(r)&&i(e)||l(r)&&l(e)||Array.isArray(r)&&Array.isArray(e)?!$(r,e):r!==e)return!1}}return!0}var G=e=>({isOnSubmit:!e||e===h,isOnBlur:e===m,isOnChange:e===g,isOnAll:e===p,isOnTouch:e===v}),Q=e=>"boolean"===typeof e,J=e=>e instanceof HTMLElement,Y=e=>"select-multiple"===e.type,K=e=>"radio"===e.type,W=e=>"string"===typeof e,z="undefined"!==typeof window&&"undefined"!==typeof window.HTMLElement&&"undefined"!==typeof document,X=e=>!J(e)||!document.contains(e);class Z{constructor(){this.tearDowns=[]}add(e){this.tearDowns.push(e)}unsubscribe(){for(const e of this.tearDowns)e();this.tearDowns=[]}}class ee{constructor(e,t){this.observer=e,this.closed=!1,t.add((()=>this.closed=!0))}next(e){this.closed||this.observer.next(e)}}class te{constructor(){this.observers=[]}next(e){for(const t of this.observers)t.next(e)}subscribe(e){const t=new Z,r=new ee(e,t);return this.observers.push(r),t}unsubscribe(){this.observers=[]}}function re(e,t){const r=B(t)?[t]:q(t),s=1==r.length?e:function(e,t){const r=t.slice(0,-1).length;let s=0;for(;s<r;)e=f(e)?s++:e[t[s++]];return e}(e,r),n=r[r.length-1];let i;s&&delete s[n];for(let a=0;a<r.slice(0,-1).length;a++){let t,s=-1;const n=r.slice(0,-(a+1)),o=n.length-1;for(a>0&&(i=e);++s<n.length;){const r=n[s];t=t?t[r]:e[r],o===s&&(l(t)&&T(t)||Array.isArray(t)&&!t.filter((e=>l(e)&&!T(e)||Q(e))).length)&&(i?delete i[r]:delete e[r]),i=t}}return e}var se=e=>"file"===e.type;const ne={value:!1,isValid:!1},ie={value:!0,isValid:!0};var ae=e=>{if(Array.isArray(e)){if(e.length>1){const t=e.filter((e=>e&&e.checked&&!e.disabled)).map((e=>e.value));return{value:t,isValid:!!t.length}}return e[0].checked&&!e[0].disabled?e[0].attributes&&!f(e[0].attributes.value)?f(e[0].value)||""===e[0].value?ie:{value:e[0].value,isValid:!0}:ie:ne}return ne},oe=(e,{valueAsNumber:t,valueAsDate:r,setValueAs:s})=>f(e)?e:t?""===e?NaN:+e:r?new Date(e):s?s(e):e;const le={isValid:!1,value:null};var ue=e=>Array.isArray(e)?e.reduce(((e,t)=>t&&t.checked&&!t.disabled?{isValid:!0,value:t.value}:e),le):le;function ce(e){const t=e.ref;if(!(e.refs?e.refs.every((e=>e.disabled)):t.disabled))return se(t)?t.files:K(t)?ue(e.refs).value:Y(t)?[...t.selectedOptions].map((({value:e})=>e)):n(t)?ae(e.refs).value:oe(f(t.value)?e.ref.value:t.value,e)}function de(e,t){if(H(e)||H(t))return t;for(const s in t){const n=e[s],i=t[s];try{e[s]=l(n)&&l(i)||Array.isArray(n)&&Array.isArray(i)?de(n,i):i}catch(r){}}return e}function fe(e,t,r,s,n){let i=-1;for(;++i<e.length;){for(const s in e[i])Array.isArray(e[i][s])?(!r[i]&&(r[i]={}),r[i][s]=[],fe(e[i][s],y(t[i]||{},s,[]),r[i][s],r[i],s)):!a(t)&&$(y(t[i]||{},s),e[i][s])?P(r[i]||{},s):r[i]=Object.assign(Object.assign({},r[i]),{[s]:!0});s&&!r.length&&delete s[n]}return r}var ye=(e,t,r)=>de(fe(e,t,r.slice(0,e.length)),fe(t,e,r.slice(0,e.length))),be=(e,t)=>!d(y(e,t,[])).length&&re(e,t),me=e=>W(e)||s.isValidElement(e),ge=e=>e instanceof RegExp;function he(e,t,r="validate"){if(me(e)||Array.isArray(e)&&e.every(me)||Q(e)&&!e)return{type:r,message:me(e)?e:"",ref:t}}var ve=e=>l(e)&&!ge(e)?e:{value:e,message:""},pe=async(e,t,r,s)=>{const{ref:i,refs:o,required:u,maxLength:c,minLength:d,min:f,max:y,pattern:b,validate:m,name:g,valueAsNumber:h,mount:v,disabled:p}=e._f;if(!v||p)return{};const V=o?o[0]:i,A=e=>{s&&V.reportValidity&&(V.setCustomValidity(Q(e)?"":e||" "),V.reportValidity())},S={},D=K(i),C=n(i),E=D||C,N=(h||se(i))&&!i.value||""===t||Array.isArray(t)&&!t.length,R=I.bind(null,g,r,S),B=(e,t,r,s=w,n=j)=>{const a=e?t:r;S[g]=Object.assign({type:e?s:n,message:a,ref:i},R(e?s:n,a))};if(u&&(!E&&(N||a(t))||Q(t)&&!t||C&&!ae(o).isValid||D&&!ue(o).isValid)){const{value:e,message:t}=me(u)?{value:!!u,message:u}:ve(u);if(e&&(S[g]=Object.assign({type:x,message:t,ref:V},R(x,t)),!r))return A(t),S}if(!N&&(!a(f)||!a(y))){let e,s;const n=ve(y),o=ve(f);if(isNaN(t)){const r=i.valueAsDate||new Date(t);W(n.value)&&(e=r>new Date(n.value)),W(o.value)&&(s=r<new Date(o.value))}else{const r=i.valueAsNumber||parseFloat(t);a(n.value)||(e=r>n.value),a(o.value)||(s=r<o.value)}if((e||s)&&(B(!!e,n.message,o.message,O,_),!r))return A(S[g].message),S}if((c||d)&&!N&&W(t)){const e=ve(c),s=ve(d),n=!a(e.value)&&t.length>e.value,i=!a(s.value)&&t.length<s.value;if((n||i)&&(B(n,e.message,s.message),!r))return A(S[g].message),S}if(b&&!N&&W(t)){const{value:e,message:s}=ve(b);if(ge(e)&&!t.match(e)&&(S[g]=Object.assign({type:F,message:s,ref:i},R(F,s)),!r))return A(s),S}if(m)if(U(m)){const e=he(await m(t),V);if(e&&(S[g]=Object.assign(Object.assign({},e),R(k,e.message)),!r))return A(e.message),S}else if(l(m)){let e={};for(const s in m){if(!T(e)&&!r)break;const n=he(await m[s](t),V,s);n&&(e=Object.assign(Object.assign({},n),R(s,n.message)),A(n.message),r&&(S[g]=e))}if(!T(e)&&(S[g]=Object.assign({ref:V},e),!r))return S}return A(!0),S};const Oe={mode:h,reValidateMode:g,shouldFocusError:!0},_e="undefined"===typeof window;function we(e={}){let t,r=Object.assign(Object.assign({},Oe),e),s={isDirty:!1,isValidating:!1,dirtyFields:{},isSubmitted:!1,submitCount:0,touchedFields:{},isSubmitting:!1,isSubmitSuccessful:!1,isValid:!1,errors:{}},o={},l=r.defaultValues||{},m=r.shouldUnregister?{}:L(l),g={action:!1,mount:!1,watch:!1},h={mount:new Set,unMount:new Set,array:new Set,watch:new Set},v=0,O={};const _={isDirty:!1,dirtyFields:!1,touchedFields:!1,isValidating:!1,isValid:!1,errors:!1},w={watch:new te,control:new te,array:new te,state:new te},j=G(r.mode),F=G(r.reValidateMode),x=r.criteriaMode===p,k=(e,t)=>!t&&(h.watchAll||h.watch.has(e)||h.watch.has((e.match(/\w+/)||[])[0])),A=async e=>{let t=!1;return _.isValid&&(t=r.resolver?T((await I()).errors):await B(o,!0),e||t===s.isValid||(s.isValid=t,w.state.next({isValid:t}))),t},S=(e,t)=>(P(s.errors,e,t),w.state.next({errors:s.errors})),D=(e,t,r)=>{const s=y(o,e);if(s){const n=y(m,e,y(l,e));f(n)||r&&r.defaultChecked||t?P(m,e,t?n:ce(s._f)):ee(e,n)}g.mount&&A()},C=(e,t,r,n=!0)=>{let i=!1;const a={name:e},o=y(s.touchedFields,e);if(_.isDirty){const e=s.isDirty;s.isDirty=a.isDirty=q(),i=e!==a.isDirty}if(_.dirtyFields&&!r){const r=y(s.dirtyFields,e);$(y(l,e),t)?re(s.dirtyFields,e):P(s.dirtyFields,e,!0),a.dirtyFields=s.dirtyFields,i=i||r!==y(s.dirtyFields,e)}return r&&!o&&(P(s.touchedFields,e,r),a.touchedFields=s.touchedFields,i=i||_.touchedFields&&o!==r),i&&n&&w.state.next(a),i?a:{}},N=(e,t)=>(P(s.dirtyFields,e,ye(t,y(l,e,[]),y(s.dirtyFields,e,[]))),be(s.dirtyFields,e)),R=async(r,n,i,a,o)=>{const l=y(s.errors,n),u=_.isValid&&s.isValid!==i;var c,d;if(e.delayError&&a?(t=t||(c=S,d=e.delayError,(...e)=>{clearTimeout(v),v=window.setTimeout((()=>c(...e)),d)}),t(n,a)):(clearTimeout(v),a?P(s.errors,n,a):re(s.errors,n)),((a?!$(l,a):l)||!T(o)||u)&&!r){const e=Object.assign(Object.assign(Object.assign({},o),u?{isValid:i}:{}),{errors:s.errors,name:n});s=Object.assign(Object.assign({},s),e),w.state.next(e)}O[n]--,_.isValidating&&!O[n]&&(w.state.next({isValidating:!1}),O={})},I=async e=>r.resolver?await r.resolver(Object.assign({},m),r.context,((e,t,r,s)=>{const n={};for(const i of e){const e=y(t,i);e&&P(n,i,e._f)}return{criteriaMode:r,names:[...e],fields:n,shouldUseNativeValidation:s}})(e||h.mount,o,r.criteriaMode,r.shouldUseNativeValidation)):{},B=async(e,t,n={valid:!0})=>{for(const i in e){const a=e[i];if(a){const e=a._f,i=V(a,"_f");if(e){const i=await pe(a,y(m,e.name),x,r.shouldUseNativeValidation);if(i[e.name]&&(n.valid=!1,t))break;t||(i[e.name]?P(s.errors,e.name,i[e.name]):re(s.errors,e.name))}i&&await B(i,t,n)}}return n.valid},q=(e,t)=>(e&&t&&P(m,e,t),!$(ae(),l)),Z=(e,t,r)=>{const s=Object.assign({},g.mount?m:f(t)?l:W(e)?{[e]:t}:t);if(e){const t=E(e).map((e=>(r&&h.watch.add(e),y(s,e))));return Array.isArray(e)?t:t[0]}return r&&(h.watchAll=!0),s},ee=(e,t,r={},s)=>{const i=y(o,e);let l=t;if(i){const r=i._f;r&&(P(m,e,oe(t,r)),l=z&&J(r.ref)&&a(t)?"":t,Y(r.ref)?[...r.ref.options].forEach((e=>e.selected=l.includes(e.value))):r.refs?n(r.ref)?r.refs.length>1?r.refs.forEach((e=>e.checked=Array.isArray(l)?!!l.find((t=>t===e.value)):l===e.value)):r.refs[0].checked=!!l:r.refs.forEach((e=>e.checked=e.value===l)):r.ref.value=l,s&&w.control.next({values:m,name:e}))}(r.shouldDirty||r.shouldTouch)&&C(e,l,r.shouldTouch),r.shouldValidate&&ie(e)},se=(e,t,r)=>{for(const s in t){const n=t[s],a=`${e}.${s}`,l=y(o,a);!h.array.has(e)&&H(n)&&(!l||l._f)||i(n)?ee(a,n,r,!0):se(a,n,r)}},ne=async e=>{const t=e.target;let i=t.name;const a=y(o,i);if(a){let c,d;const f=t.type?ce(a._f):t.value,g=e.type===b,h=!((l=a._f).mount&&(l.required||l.min||l.max||l.maxLength||l.minLength||l.pattern||l.validate))&&!r.resolver&&!y(s.errors,i)&&!a._f.deps||((e,t,r,s,n)=>!n.isOnAll&&(!r&&n.isOnTouch?!(t||e):(r?s.isOnBlur:n.isOnBlur)?!e:!(r?s.isOnChange:n.isOnChange)||e))(g,y(s.touchedFields,i),s.isSubmitted,F,j),v=k(i,g);g?a._f.onBlur&&a._f.onBlur(e):a._f.onChange&&a._f.onChange(e),P(m,i,f);const p=C(i,f,g,!1),V=!T(p)||v;if(!g&&w.watch.next({name:i,type:e.type}),h)return V&&w.state.next(Object.assign({name:i},v?{}:p));if(!g&&v&&w.state.next({}),O[i]=(O[i],1),_.isValidating&&w.state.next({isValidating:!0}),r.resolver){const{errors:e}=await I([i]);if(c=y(e,i),n(t)&&!c){const t=u(i),r=y(o,t);if(Array.isArray(r)&&r.every((e=>e._f&&n(e._f.ref)))){const r=y(e,t,{});r.type&&(c=r),i=t}}d=T(e)}else c=(await pe(a,y(m,i),x,r.shouldUseNativeValidation))[i],d=await A(!0);a._f.deps&&ie(a._f.deps),R(!1,i,d,c,p)}var l},ie=async(e,t={})=>{let n,i;const a=E(e);if(w.state.next({isValidating:!0}),r.resolver){const t=await(async e=>{const{errors:t}=await I();if(e)for(const r of e){const e=y(t,r);e?P(s.errors,r,e):re(s.errors,r)}else s.errors=t;return t})(f(e)?e:a);n=T(t),i=e?!a.some((e=>y(t,e))):n}else e?(i=(await Promise.all(a.map((async e=>{const t=y(o,e);return await B(t&&t._f?{[e]:t}:t)})))).every(Boolean),A()):i=n=await B(o);return w.state.next(Object.assign(Object.assign({},W(e)&&n===s.isValid?{name:e}:{}),{errors:s.errors,isValid:n,isValidating:!1})),t.shouldFocus&&!i&&M(o,(e=>y(s.errors,e)),e?a:h.mount),i},ae=e=>{const t=Object.assign(Object.assign({},l),g.mount?m:{});return f(e)?t:W(e)?y(t,e):e.map((e=>y(t,e)))},le=(e,t={})=>{for(const n of e?E(e):h.mount)h.mount.delete(n),h.array.delete(n),y(o,n)&&(t.keepValue||(re(o,n),re(m,n)),!t.keepError&&re(s.errors,n),!t.keepDirty&&re(s.dirtyFields,n),!t.keepTouched&&re(s.touchedFields,n),!r.shouldUnregister&&!t.keepDefaultValue&&re(l,n));w.watch.next({}),w.state.next(Object.assign(Object.assign({},s),t.keepDirty?{isDirty:q()}:{})),!t.keepIsValid&&A()},ue=(e,t={})=>{const s=y(o,e);return P(o,e,{_f:Object.assign(Object.assign(Object.assign({},s&&s._f?s._f:{ref:{name:e}}),{name:e,mount:!0}),t)}),h.mount.add(e),!f(t.value)&&P(m,e,t.value),s?Q(t.disabled)&&P(m,e,t.disabled?void 0:y(m,e,ce(s._f))):D(e,!0),_e?{name:e}:Object.assign(Object.assign({name:e},Q(t.disabled)?{disabled:t.disabled}:{}),{onChange:ne,onBlur:ne,ref:s=>{if(s){ue(e,t);let r=y(o,e);const i=f(s.value)&&s.querySelectorAll&&s.querySelectorAll("input,select,textarea")[0]||s,a=(e=>K(e)||n(e))(i);if(i===r._f.ref||a&&d(r._f.refs||[]).find((e=>e===i)))return;r={_f:a?Object.assign(Object.assign({},r._f),{refs:[...d(r._f.refs||[]).filter((e=>J(e)&&document.contains(e))),i],ref:{type:i.type,name:e}}):Object.assign(Object.assign({},r._f),{ref:i})},P(o,e,r),(!t||!t.disabled)&&D(e,!1,i)}else{const s=y(o,e,{}),n=r.shouldUnregister||t.shouldUnregister;s._f&&(s._f.mount=!1),n&&(!c(h.array,e)||!g.action)&&h.unMount.add(e)}}})};return{control:{register:ue,unregister:le,_getWatch:Z,_getDirty:q,_updateValid:A,_removeUnmounted:()=>{for(const e of h.unMount){const t=y(o,e);t&&(t._f.refs?t._f.refs.every(X):X(t._f.ref))&&le(e)}h.unMount=new Set},_updateFieldArray:(e,t,r,n=[],i=!0,a=!0)=>{if(g.action=!0,a&&y(o,e)){const s=t(y(o,e),r.argA,r.argB);i&&P(o,e,s)}if(Array.isArray(y(s.errors,e))){const n=t(y(s.errors,e),r.argA,r.argB);i&&P(s.errors,e,n),be(s.errors,e)}if(_.touchedFields&&y(s.touchedFields,e)){const n=t(y(s.touchedFields,e),r.argA,r.argB);i&&P(s.touchedFields,e,n),be(s.touchedFields,e)}(_.dirtyFields||_.isDirty)&&N(e,n),w.state.next({isDirty:q(e,n),dirtyFields:s.dirtyFields,errors:s.errors,isValid:s.isValid})},_getFieldArray:e=>y(g.mount?m:l,e,[]),_subjects:w,_proxyFormState:_,get _fields(){return o},set _fields(e){o=e},get _formValues(){return m},set _formValues(e){m=e},get _stateFlags(){return g},set _stateFlags(e){g=e},get _defaultValues(){return l},set _defaultValues(e){l=e},get _names(){return h},set _names(e){h=e},get _formState(){return s},set _formState(e){s=e},get _options(){return r},set _options(e){r=Object.assign(Object.assign({},r),e)}},trigger:ie,register:ue,handleSubmit:(e,t)=>async n=>{n&&(n.preventDefault&&n.preventDefault(),n.persist&&n.persist());let i=!0,a=Object.assign({},m);w.state.next({isSubmitting:!0});try{if(r.resolver){const{errors:e,values:t}=await I();s.errors=e,a=t}else await B(o);T(s.errors)&&Object.keys(s.errors).every((e=>y(a,e)))?(w.state.next({errors:{},isSubmitting:!0}),await e(a,n)):(t&&await t(s.errors,n),r.shouldFocusError&&M(o,(e=>y(s.errors,e)),h.mount))}catch(l){throw i=!1,l}finally{s.isSubmitted=!0,w.state.next({isSubmitted:!0,isSubmitting:!1,isSubmitSuccessful:T(s.errors)&&i,submitCount:s.submitCount+1,errors:s.errors})}},watch:(e,t)=>U(e)?w.watch.subscribe({next:r=>e(Z(void 0,t),r)}):Z(e,t,!0),setValue:(e,t,r={})=>{const n=y(o,e),i=h.array.has(e);P(m,e,t),i?(w.array.next({name:e,values:m}),(_.isDirty||_.dirtyFields)&&r.shouldDirty&&(N(e,t),w.state.next({name:e,dirtyFields:s.dirtyFields,isDirty:q(e,t)}))):!n||n._f||a(t)?ee(e,t,r,!0):se(e,t,r),k(e)&&w.state.next({}),w.watch.next({name:e})},getValues:ae,reset:(t,r={})=>{const n=!T(t),i=t||l,a=L(i);if(r.keepDefaultValues||(l=i),!r.keepValues){if(z)for(const e of h.mount){const t=y(o,e);if(t&&t._f){const e=Array.isArray(t._f.refs)?t._f.refs[0]:t._f.ref;try{J(e)&&e.closest("form").reset();break}catch(u){}}}m=e.shouldUnregister?{}:a,o={},w.control.next({values:n?a:l}),w.watch.next({}),w.array.next({values:a})}h={mount:new Set,unMount:new Set,array:new Set,watch:new Set,watchAll:!1,focus:""},w.state.next({submitCount:r.keepSubmitCount?s.submitCount:0,isDirty:r.keepDirty?s.isDirty:!!r.keepDefaultValues&&$(t,l),isSubmitted:!!r.keepIsSubmitted&&s.isSubmitted,dirtyFields:r.keepDirty?s.dirtyFields:{},touchedFields:r.keepTouched?s.touchedFields:{},errors:r.keepErrors?s.errors:{},isSubmitting:!1,isSubmitSuccessful:!1}),g.mount=!_.isValid||!!r.keepIsValid,g.watch=!!e.shouldUnregister},clearErrors:e=>{e?E(e).forEach((e=>re(s.errors,e))):s.errors={},w.state.next({errors:s.errors})},unregister:le,setError:(e,t,r)=>{const n=(y(o,e,{_f:{}})._f||{}).ref;P(s.errors,e,Object.assign(Object.assign({},t),{ref:n})),w.state.next({name:e,errors:s.errors,isValid:!1}),r&&r.shouldFocus&&n&&n.focus&&n.focus()},setFocus:e=>y(o,e)._f.ref.focus()}}function je(e={}){const t=s.useRef(),[r,n]=s.useState({isDirty:!1,isValidating:!1,dirtyFields:{},isSubmitted:!1,submitCount:0,touchedFields:{},isSubmitting:!1,isSubmitSuccessful:!1,isValid:!1,errors:{}});t.current?t.current.control._options=e:t.current=Object.assign(Object.assign({},we(e)),{formState:r});const i=t.current.control;return R({subject:i._subjects.state,callback:e=>{C(e,i._proxyFormState,!0)&&(i._formState=Object.assign(Object.assign({},i._formState),e),n(Object.assign({},i._formState)))}}),s.useEffect((()=>{i._stateFlags.mount||(i._proxyFormState.isValid&&i._updateValid(),i._stateFlags.mount=!0),i._stateFlags.watch&&(i._stateFlags.watch=!1,i._subjects.state.next({})),i._removeUnmounted()})),t.current.formState=D(r,i._proxyFormState),t.current}}}]);