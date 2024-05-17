$(".js-remove-class").removeClass("show active");

$(".js-enable").attr("style", "height: auto !important;");

$(".js-remove-border").addClass("border-top-0");

switch ($("#jumpToTab").val()) {
    case "CVC":
        $("#pills-cvc-tab").click();
        break;
    case "RSC":
        $("#pills-rsc-tab").click();
        break;
    case "Lists":
        $("#pills-lists-tab").click();
        break;
    case "TLS":
        $("#pills-tls-tab").click();
        break;
    case "KeyStores":
        $("#pills-keyStores-tab").click();
        break;
    case "Certificates":
        $("#pills-certificates-tab").click();
        break;
    case "KeyPairs":
        $("#pills-keyPairs-tab").click();
        break;
    default:
        break;
}
