const ctx = document.getElementById('trafficChart');

new Chart(ctx, {

type: 'line',

data: {

labels: ["1","2","3","4","5"],

datasets: [{

label: "Network Traffic",

data: [10,20,15,25,30],

borderWidth: 2

}]

}

});