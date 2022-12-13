$("#copyButton").show();

$("#copyButton").click(function(){
    var copyText = document.getElementById("mailText");
    copyText.select();
    navigator.clipboard.writeText(copyText.value);
    $("#copied").fadeIn('fast');
    setTimeout(function() {
        $('#copied').fadeOut('fast');
    }, 1000);
});
