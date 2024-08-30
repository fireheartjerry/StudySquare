function renderLatex() {
    var katexElements = document.querySelectorAll('span[class^="katex--"]');
    var len = katexElements.length;
    if (len > 0) {
        for(var i = len-1 ; i >= 0; i--) {
            var currElement = katexElements[i];
            var katexDefinition = currElement.textContent;
            try {
                var katexHTML = katex.renderToString(katexDefinition, { displayMode: currElement.className=="katex--display" });
                currElement.insertAdjacentHTML('beforebegin', katexHTML);
                currElement.remove();
            } catch(err) {
                alert(err);
                console.error(err);
            }
        }
    }
}