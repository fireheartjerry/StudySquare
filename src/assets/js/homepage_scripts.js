/*!
* Start Bootstrap - Modern Business v5.0.7 (https://startbootstrap.com/template-overviews/modern-business)
* Copyright 2013-2023 Start Bootstrap
* Licensed under MIT (https://github.com/StartBootstrap/startbootstrap-modern-business/blob/master/LICENSE)
*/
var texts=["robust practice platform.","supportive community of problem solvers.","host of original math contests.", "better way to improve."],currentWord=0,currentLetter=0,direction=1,delay=0,reverse=!1;setInterval(function(){var e=document.getElementById("typingText");currentLetter+=direction,0==direction?--delay<=0&&(direction=reverse?1:-1):currentLetter==texts[currentWord].length?(direction=0,delay=12,reverse=!1):0==currentLetter&&(direction=0,delay=8,reverse=!0,currentWord=(currentWord+1)%texts.length),e.innerHTML=texts[currentWord].substring(0,currentLetter)},75);
