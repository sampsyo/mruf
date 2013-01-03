$(function() {
    // Support non-standard form methods using a server-side middleware that
    // looks for a special query parameter.
    $('form[method!="POST"][method!="GET"]').each(function(i, formEl) {
        var form = $(formEl);
        var action = form.attr('action') + 
                     '?__METHOD_OVERRIDE__=' + 
                     form.attr('method');
        form.attr('action', action);
        form.attr('method', 'POST');
    });
});
