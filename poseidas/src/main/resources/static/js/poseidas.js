document.addEventListener('DOMContentLoaded', function(event) {
    $('ul.navbar-nav a[href="'+  window.location.pathname +'"]').parent().addClass('active');
    $(".jumbotron").css('padding-bottom','1em');
    $(".jumbotron").css('padding-top','2em');
    $('[data-toggle="tooltip"]').tooltip();
});


