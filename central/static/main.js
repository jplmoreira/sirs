$(document).ready(function () {
    $('form').on('submit', function (event) {
        const passphrase = $('#passphrase').val();
        const mac_address = $('#mac_address').val();

        if (passphrase.length < 16) {
            return;
        }

        const id = sha512(mac_address, passphrase);

        console.log("passphrase: " + passphrase);
        console.log("sha512(passphrase): " + id);

        /* set button loading */
        const spinner = $('#spinner');
        const table = $('table');
        spinner.show();

        $.ajax({
            data: {
                id: id,
            },
            type: 'POST',
            url: '/pass'
        })
            .done(function (data) {
                spinner.hide();

                for (let i = 0; i < data.length; i++) {
                    const json = decipher(passphrase, data[i]);
                    const device = JSON.parse(json);

                    // $('table tr:last').after('<tr>...</tr><tr>...</tr>');

                    /*   $('table > tbody:last-child').append(
                           $('<tr>').append('<td>').append()
                       );
   */
                    // const location = $('<td>').text(device['location']);
                    // const mac = $('<td>').text(device['mac']);
                    // const timestamp = $('<td>').text(device['timestamp']);
                    // $('table > tr:last-child').append($('<tr>').append(location).append(mac).append(timestamp))
                    let tr = document.createElement("tr");
                    let td1 = document.createElement("td");
                    td1.innerHTML = device['mac'];
                    let td2 = document.createElement("td");
                    td2.innerHTML = device['location'];
                    let td3 = document.createElement("td");
                    let date = new Date(device['timestamp'] * 1000);
                    td3.innerHTML = date.toUTCString();
                    // td3.innerHTML = device['timestamp'];
                    $(tr).append(td1);
                    $(tr).append(td2);
                    $(tr).append(td3);
                    $(table).append(tr);
                    spinner.hide();
                }


                // var table = document.createElement("table");
                // const table = $('table');
                // let tr = document.createElement("tr");
                // let td1 = document.createElement("td");
                // td1.innerHTML = "device";
                // let td2 = document.createElement("td");
                // td2.innerHTML = "location";
                // let td3 = document.createElement("td");
                // td3.innerHTML = "time";
                // $(tr).append(td1);
                // $(tr).append(td2);
                // $(tr).append(td3);
                // $(table).append(tr);
                // for (let i = 0; i < data.length; i++) {
                //     const json = decipher(passphrase, data[i]);
                //     console.log(json);
                //     const device = JSON.parse(json);
                //     tr = document.createElement("tr");
                //     td1 = document.createElement("td");
                //     td1.innerHTML = device['mac'];
                //     td2 = document.createElement("td");
                //     td2.innerHTML = device['location'];
                //     td3 = document.createElement("td");
                //     td3.innerHTML = device['timestamp'];
                //     $(tr).append(td1);
                //     $(tr).append(td2);
                //     $(tr).append(td3);
                //     $(table).append(tr);
                // }
                // $("body").append(table)
            });
        event.preventDefault();
    });
});
