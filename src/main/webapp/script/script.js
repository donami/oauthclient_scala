function formatJson() {
    var json = JSON.parse(document.getElementById("jsonUserInfo").innerHTML);
    var elem = document.getElementById("debugContent");

    elem.innerHTML= "";

    elem.appendChild(createTableFromObject(json, Array("Key", "Value")));
}


function createTableFromObject(obj, headings = Array()) {
    var table = createElement("table");
    table.classList.add("ui");
    table.classList.add("table");

    if (headings.length > 0) {
        var thead = createElement("thead");

        var tr = createElement("tr");

        headings.forEach(value => {
            tr.appendChild(createElement("th", value));
        });

        thead.appendChild(tr);

        table.appendChild(thead);
    }

    var tbody = createElement("tbody");

    Object.keys(obj).forEach(key => {
        var tr = createElement("tr");

        var tdKey = createElement("td", key);
        var tdValue = createElement("td", obj[key]);

        if (typeof(obj[key]) != "object") {
            tdValue = createElement("td", obj[key]);
        }
        else {
            tdKey.classList.add("top");
            tdKey.classList.add("aligned");

            tdValue = createElement("td");
            tdValue.appendChild(createTableFromObject(obj[key], Array("Key", "Value")));
        }

        tr.appendChild(tdKey);
        tr.appendChild(tdValue);

        tbody.appendChild(tr);
    })

    table.appendChild(tbody);

    return table;
}

function createElement(type, content = null) {
    var elem = document.createElement(type);

    if (content !== null) {
        elem.appendChild(document.createTextNode(content));
    }

    return elem;
}

function toggleDebugWindow() {
    var modalElemWrapper = document.getElementById("modalWrapper");
    var modalElem = document.getElementById("modal");

    formatJson();

    modalElemWrapper.classList.toggle("visible");
    modalElemWrapper.classList.toggle("active");

    modalElem.classList.toggle("visible");
    modalElem.classList.toggle("active");
}

