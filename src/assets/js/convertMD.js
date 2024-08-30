function md2html_interactive(start_msg) {
    return new Promise((resolve) => {
        var ret_html, ret_md;
        const stackedit = new Stackedit();
        stackedit.openFile({ content: { text: start_msg } });
        stackedit.on("fileChange", (file) => {
            ret_md = file.content.text;
            ret_html = file.content.html;
        }); stackedit.on("close", () => {
            resolve({
                md: ret_md,
                html: ret_html,
            });
        });
    });
}

function md2html_hidden(markdown) {
    return new Promise((resolve) => {
        const stackedit = new Stackedit();
        stackedit.openFile({ content: { text: markdown } }, true);
        stackedit.on('fileChange', (file) => { resolve(file.content.html); });
    });
}