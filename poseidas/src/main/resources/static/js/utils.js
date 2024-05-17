$(document).ready(function() {
    // Finde alle HTML-Elemente mit der Klasse "scrolldown" und Scrollleiste
    $(".scrolldown").each(function() {
        // Setze die Scrollposition jedes gefundene Elements auf das Ende
        this.scrollTop = this.scrollHeight;
    });
});