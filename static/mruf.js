// Given a number of cents, return a human-readable price string.
function penniesToPrice(pennies) {
    return '$' + (pennies / 100).toFixed(2);
}

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

    // Total up orders on order-placing page.
    $('input.orderCount').change(function() {
        var total = 0;
        $('.orderProduct').each(function(i, product) {
            var price = parseInt($(product).data('price'));
            var count = parseInt($(product).find('input.orderCount').val());
            if (count > 0) {
                total += price * count;
            }
        });
        $('#orderTotal').text(penniesToPrice(total));
    });
});
