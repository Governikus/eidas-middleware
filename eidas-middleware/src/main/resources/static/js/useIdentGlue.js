/*
 * Copyright (c) 2023 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

$(function () {

    if (AusweisApp2.isMobile()) {
        $("#goToAa2").attr("href", getEIDLink(true));
        $("#eid-install-app-hint").removeAttr("hidden");
        $("#eid-install-stationary").attr("hidden", "hidden");
    } else {
        // Stationary Status
        const observer = new AusweisApp2.StationaryStatusObserver((status) => {
            console.log("new status", status);
            if (status.status === "available") {
                $("#client-inactive").attr("hidden", "hidden");
                $("#client-active").removeAttr("hidden");
            } else if (status.status === "safari") {
                $("#client-inactive").attr("hidden", "hidden");
                $("#client-active").attr("hidden", "hidden");
            } else {
                $("#client-active").attr("hidden", "hidden");
                $("#client-inactive").removeAttr("hidden");
            }
        });
        observer.observe();
        $("#goToAa2").attr("href", getEIDLink(false));
    }
});

function getEIDLink(isMobile) {
    return AusweisApp2.getClientURL({
        mobile: isMobile,
        action: "connect",
        tcTokenURL: $("#tcTokenURL")[0].innerText
    })
}