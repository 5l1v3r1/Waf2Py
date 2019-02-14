<script src="/Waf2Py/static/bower_components/chart.js/chart.bundle.js"></script>

<script>
   function logs() {
   $.ajax({
   type: "GET",
   url: "/Logs/WafLogs_frame/{{=id_rand}}",
   success: function(data){
            //var mystring = data
            var mainDiv = "";
           
            var parsedJSON = JSON.stringify(data);
            var jsonData = JSON.parse(parsedJSON);
            var total_critical = 0;
            if (jsonData['data'] != '') {

                for (var i = 0; i < jsonData['data'].length; i++) {
                    //	alert(parsedJSON[i].Id);
                    var parsed = JSON.parse(jsonData['data'][i])
                    //console.log(parsed['transaction'])
                    if (mainDiv !== 'created') {
                        //Main div
                        var iDiv1 = document.createElement('div');
                        iDiv1.className = 'col-lg-12';

                        var mainDiv = 'created';
                        //panel group div
                        var PanelGroup = document.createElement('div');
                        PanelGroup.className = 'box-group';
                        PanelGroup.id = 'accordion-logs';
                        iDiv1.appendChild(PanelGroup);
                        
                        
                    }
                   //Panel default
                    var PanelDefault = document.createElement('div');
                    PanelDefault.className = 'box box-default';
                    PanelGroup.appendChild(PanelDefault);

                    //Panel heading
                    var PanelHeading = document.createElement('div');
                    PanelHeading.className = 'box-header';
                    PanelDefault.appendChild(PanelHeading);

                    //title h4
                    var H4 = document.createElement('h4');
                    H4.className = 'box-title';
                    PanelHeading.appendChild(H4);

                    //a tag
                    var A = document.createElement('a');
                    A.className = 'collapsed';
                    A.setAttribute("data-toggle", "collapse");
                    A.setAttribute("data-parent", "#accordion-logs");
                    A.setAttribute("href", "#collapse" + i);
                    A.setAttribute("aria-expanded", "false");
                    H4.appendChild(A);

               
                    //add vuln title
                    response_code = parsed['transaction']['response']['http_code']
                    if (parsed['transaction']['messages'][0] != null) {
                            var severity_string = parsed['transaction']['messages'][0]['details']['severity']
                            var title = parsed['transaction']['messages'][0]['message'] + '  ';
                            var attack_info = parsed['transaction']['messages'][0]['details']['data'];
                            var modsec_info = parsed['transaction']['messages'][0]['details'];
                            var ruleId = parsed['transaction']['messages'][0]['details']['ruleId']
                            var uri = parsed['transaction']['request']['uri']
                            var addBtn = 'yes';
                        }
                    
                    else if (String(response_code).startsWith(5)) {
                        
                        var severity_string = 'ERROR'
                        var title = 'Server Error - Code: '+ String(response_code)+' '
                        var attack_info = 'An error '+ String(response_code) + ' was produced in: '+parsed['transaction']['request']['uri'];
                        var modsec_info = {'Information':'This is not an attack, check the error log tab for more information'} ;
                        var addBtn = 'no';
                    }
                    
                    else {
                            var severity_string = 'ERROR'
                            var title = 'Server Error - Code: '+ String(response_code)+' '
                            var attack_info = 'An error '+ String(response_code) + ' was produced in: '+parsed['transaction']['request']['uri'];
                            var modsec_info = {'Information':'This is not an attack, check the access log tab for more information'} ;
                            var addBtn = 'no';
                        }
                    //var severity_string = parsed['transaction']['messages'][0]['details']['severity']
                   var attack_div = document.createElement('div');
                    if (severity_string === "CRITICAL" || severity_string === "2") {
                        severity_string = "CRITICAL"
                        attack_div.style = "white-space: pre-wrap; background: red; border-radius: 3px"
                        color = '#f03154';
                        total_critical++
                    }
                    else if (severity_string === "WARNING" || severity_string === "3") {
                        severity_string = "WARNING"
                        attack_div.style = "white-space: pre-wrap; background: #f39c12; border-radius: 3px";
                        color = '#f39c12';
                    }
                    else if (severity_string === "NOTICE" || severity_string === "4") {
                        color = '#5cb45b';
                        attack_div.style = "white-space: pre-wrap; background: #00a65a; border-radius: 3px"
                        severity_string = "NOTICE"
                    }
                    else if (severity_string === "ERROR" || severity_string === "5") {
                        color = '#2a323c';
                        attack_div.style = "white-space: pre-wrap; background: #d2d6de; border-radius: 3px"
                        severity_string = "ERROR"
                    }
                    else if (severity_string === "No severity set in rules") {
                        severity_string = "No severity set in rules"
                        color = '#5cb45b';
                    }
                    var s = document.createTextNode(severity_string);
                    var date = document.createTextNode('#' + (i + 1) + ' - ' + parsed['transaction']['time_stamp'] + ' - ');
                    //var color = '#f7b543';
                    var T = document.createElement('font')
                    var F = document.createElement('font');
                    F.color = color;
                    T.color = "#006B98";
                    
                    A.appendChild(date);
                    T.appendChild(document.createTextNode(title));
                    A.appendChild(T);
                    A.appendChild(F);

                    F.appendChild(s);

                    //panel collapse
                    var PanelCollapse = document.createElement('div');
                    PanelCollapse.className = 'panel-collapse collapse'
                    PanelCollapse.id = 'collapse' + i
                    PanelCollapse.setAttribute("aria-expanded", "false");
                    //panel body
                    var PanelBody = document.createElement('div');
                    PanelBody.className = 'box-body';
                    var audit_info = parsed['transaction']['request']['body'];
                    
                    var attacker = parsed['transaction']['client_ip'];
                    
                    //get headers
                    var div_header = document.createElement('div');
                    div_header.setAttribute("id", "div_header_"+i)
                    //Create table inside headers div
                    var table_headers = document.createElement('table');
                    table_headers.style = "border: 1px; width: 800px"
                    table_headers_tr = document.createElement('tr');
                    table_headers_th = document.createElement('th');
                    table_headers_th1 = document.createElement('th');
                    table_headers_th.appendChild(document.createTextNode(' '));
                    table_headers_th1.appendChild(document.createTextNode('\t'+' '));
                    table_headers_tr.appendChild(table_headers_th);
                    table_headers_tr.appendChild(table_headers_th1);
                    table_headers.appendChild(table_headers_tr)
                    table_headers_td = document.createElement('td');

                    
                    var headers = parsed['transaction']['request']['headers'];
                    var headers_keys = Object.keys(headers);
                    //console.log(parsed['transaction'])    

                    td_method = document.createElement('td')
                    tr_method = document.createElement('tr')
                    td_method_data = document.createElement('td')
                    td_method.appendChild(document.createTextNode('Method:'))
                    td_method_data.appendChild(document.createTextNode('\t'+parsed['transaction']['request']['method']+ '\n'))
                    tr_method.appendChild(td_method)
                    tr_method.appendChild(td_method_data)
                    
                    //GeoIP
                    //Contry name
                    td_country_name = document.createElement('td')
                    tr_country_name = document.createElement('tr')
                    td_country_name_data = document.createElement('td')
                    td_country_name.appendChild(document.createTextNode('Country:'))
                    td_country_name_data.appendChild(document.createTextNode('\t'+parsed['transaction']['country']+ '\n'))
                    tr_country_name.appendChild(td_country_name)
                    tr_country_name.appendChild(td_country_name_data)
                    
                    //City
                    td_city = document.createElement('td')
                    tr_city = document.createElement('tr')
                    td_city_data = document.createElement('td')
                    td_city.appendChild(document.createTextNode('City:'))
                    td_city_data.appendChild(document.createTextNode('\t'+parsed['transaction']['city']+ '\n'))
                    tr_city.appendChild(td_city)
                    tr_city.appendChild(td_city_data)
                    
                    //uri
                    tr_uri = document.createElement('tr')
                    td_uri = document.createElement('td')
                    td_uri_data = document.createElement('td')
                    td_uri.appendChild(document.createTextNode('Uri:'))
                    td_uri_data.appendChild(document.createTextNode('\t'+parsed['transaction']['request']['uri']+ '\n'))
                    tr_uri.appendChild(td_uri)
                    tr_uri.appendChild(td_uri_data)
                    
                    //version
                    tr_version = document.createElement('tr')
                    td_version = document.createElement('td')
                    td_version_data = document.createElement('td')
                    td_version.appendChild(document.createTextNode('Version:'))
                    td_version_data.appendChild(document.createTextNode('\t'+parsed['transaction']['request']['http_version'] + '\n'))
                    tr_version.appendChild(td_version)
                    tr_version.appendChild(td_version_data)
                    
                    
                    table_headers.appendChild(tr_city)
                    table_headers.appendChild(tr_country_name)
                    table_headers.appendChild(tr_method)
                    table_headers.appendChild(tr_uri)
                    table_headers.appendChild(tr_version)
                    //loop for headers values
                    for (var h = 0; h < headers_keys.length; h++) {
                        bold_header = document.createElement('b');
                        table_headers_tr = document.createElement('tr');
                        table_headers_td = document.createElement('td');
                        
                        table_headers_td2 = document.createElement('td');
                        
                        //bold_header.appendChild(document.createTextNode(headers_keys[h]+':'));
                        table_headers_td.appendChild(document.createTextNode(headers_keys[h]+':'));
                        table_headers_td2.appendChild(document.createTextNode('\t'+headers[headers_keys[h]] + '\n'))
                        table_headers_tr.appendChild(table_headers_td)
                        table_headers_tr.appendChild(table_headers_td2)
                        table_headers.appendChild(table_headers_tr)
                        //div_header.appendChild(bold_header)
                        //div_header.appendChild(document.createTextNode(':\t'+headers[headers_keys[h]] + '\n'))
                        //all_headers += headers_keys[h] + ': ' + headers[headers_keys[h]] + '\n'
                    }
                    
                    
                    div_header.appendChild(table_headers)
                    
                    //get modsec info
                    //var modsec_info = parsed['transaction']['messages'][0]['details'];
                    var modsec_info_keys = Object.keys(modsec_info);
                    var all_modsec_info = '';
                    //Create table for modsec info
                    table_modsec = document.createElement('table')
                    table_modsec.style = "border: 1px; width: 800px"
                    tr_modsec = document.createElement('tr')
                    th_modsec = document.createElement('th')
                    th_modsec.appendChild(document.createTextNode(' '))
                    th_modsec.appendChild(document.createTextNode('\t'+' '))
                    tr_modsec.appendChild(th_modsec)
                    table_modsec.appendChild(tr_modsec)
                    
                    for (var m = 0; m < modsec_info_keys.length; m++) {
                        tr_modsec_info = document.createElement('tr')
                        td_modsec_info = document.createElement('td')
                        td_modsec_info.appendChild(document.createTextNode(modsec_info_keys[m]+':'))
                        td_modsec_info.appendChild(document.createTextNode('\t'+modsec_info[modsec_info_keys[m]] + '\n'))
                        tr_modsec_info.appendChild(td_modsec_info)
                        table_modsec.appendChild(tr_modsec_info)
                    }
                    console.log(parsed['transaction'])
                    div_modsec = document.createElement('div')
                    div_modsec.setAttribute("id","attack_div_"+i)
                    div_modsec.appendChild(table_modsec)
                    var textdata = document.createTextNode(audit_info);
                    //attack div
                    
                    
                    //attack_div.style = "white-space: pre-wrap; background: red; border-radius: 3px";
                    var fontAttack = document.createElement('font');
                    fontAttack.color = "#FFFFFF";
                    var attack = document.createTextNode(attack_info);
                    var fontAttackBold = document.createElement('b');


                    //attacker info
                    var attacker_div = document.createElement('div');
                    attacker_div.style = "white-space: pre-wrap; border-radius: 3px; border-color: white;";
                    attacker_div.setAttribute("class","bg-orange-active color-palette")
                    //country flag
                    var country_flag = document.createElement('img')
                    country_flag.setAttribute("class","flag flag-"+parsed['transaction']['country_code'].toLowerCase())
                    country_flag.setAttribute("src", "blank.gif")
                    var fontAttacker = document.createElement('font');
                    fontAttacker.color = "#FFFFFF";
                    var fontAttackerBold = document.createElement('b');
                    var attacker_ip = document.createTextNode("Attacker IP: " + attacker+'      ');
                    
                    var body_desc = document.createTextNode("Body");
                    var info = document.createTextNode("Attack info");


                    var divButton = document.createElement('div');
                    divButton.style = "float: right";

                    var body = document.createElement('div');
                    
                    var header_sec_title = document.createElement('h1')
                    var header_sec_title_sm = document.createElement('small')
                    var header_sec_text = document.createTextNode("Headers");
                    header_sec_title_sm.appendChild(header_sec_text);
                    header_sec_title.appendChild(header_sec_title_sm);
                    var btn1 = document.createElement('a')
                    var btn2 = document.createElement('a')
                    var btn3 = document.createElement('a')
                    btn1.setAttribute("onclick","Toggle("+i+")")
                    btn1.appendChild(header_sec_text)
                    btn2.appendChild(body_desc)
                    btn2.setAttribute("onclick","ToggleBody("+i+")")
                    btn3.setAttribute("onclick","ToggleAttack("+i+")")
                    btn3.appendChild(info)
                    btn1.setAttribute("class", "btn btn-sm btn-primary")
                    btn2.setAttribute("class", "btn btn-sm btn-primary")
                    btn3.setAttribute("class", "btn btn-sm btn-danger")
                    body.style = "overflow-x: auto; white-space: pre-wrap;"
                    body.appendChild(header_sec_title)
                    body.appendChild(document.createElement('br'))
                    div_header.style = "white-space: pre-wrap;"
                    
                    //div_header.appendChild(document.createTextNode(all_headers));
                    body.appendChild(btn1)
                    body.appendChild(div_header)
                    body.appendChild(document.createElement('hr'))
                    body.appendChild(btn2)
                    body.appendChild(document.createElement('br'))
                    //body.appendChild(document.createTextNode("Body:\n"))
                    body.appendChild(textdata);
                    body.appendChild(document.createElement('hr'))
                    body.appendChild(btn3)
                    body.appendChild(document.createElement('br'))
                    body.appendChild(div_modsec)
                    //body.appendChild(document.createTextNode(all_modsec_info))
                    attack_div.appendChild(fontAttack);
                    fontAttack.appendChild(fontAttackBold);
                    fontAttackBold.appendChild(attack);

                    fontAttacker.appendChild(fontAttackerBold);
                    fontAttackerBold.appendChild(attacker_ip);
                    attacker_div.appendChild(fontAttacker);
                    attacker_div.appendChild(country_flag);
                    // Exclusions
                    if ( addBtn === 'yes') {
                        div_actions = document.createElement('div')
                        div_actions.setAttribute("class","btn-group pull-right")
                        acctionButtons = document.createElement('button');
                        acctionButtons.appendChild(document.createTextNode("Exclusions"))
                        acctionButtons.setAttribute("class", "btn btn-info dropdown-toggle");
                        acctionButtons.setAttribute("type", "button");
                        acctionButtons.setAttribute("data-toggle", "dropdown");
                        spanActButton = document.createElement('span')
                        spanActButton.setAttribute("class", "caret");
                        acctionButtons.appendChild(spanActButton)
                        div_actions.appendChild(acctionButtons)
                        ulActButton = document.createElement('ul')
                        ulActButton.setAttribute("class", "dropdown-menu");
                        liActButton = document.createElement('li')
                        aActButton1 = document.createElement('a')
                        aActButton1.setAttribute("href", "#");
                        aActButton1.setAttribute("onclick", "GlobalExclusion('"+ruleId+"', "+"'"+title+"',)");
                        aActButton1.appendChild(document.createTextNode("Global exclusion"))

                        liActButton2 = document.createElement('li')
                        aActButton2 = document.createElement('a')
                        aActButton2.setAttribute("href", "#");
                        aActButton2.setAttribute("onclick", "LocalExclusion('"+ruleId+"', "+"'"+title+"', "+"'"+uri+"')");
                        aActButton2.appendChild(document.createTextNode("Local exclusion"))

                        liActButton.appendChild(aActButton1)
                        liActButton2.appendChild(aActButton2)

                        ulActButton.appendChild(liActButton)
                        ulActButton.appendChild(liActButton2)

                        div_actions.appendChild(ulActButton)
                    }
                    
                    
                    //PanelBody.appendChild(document.createElement('br'));
                    PanelBody.appendChild(document.createElement('br'));
                    PanelBody.appendChild(attack_div);
                    PanelBody.appendChild(attacker_div);
                    PanelBody.appendChild(document.createElement('br'));
                    if ( addBtn === 'yes') {
                        PanelBody.appendChild(div_actions);
                    }
                    PanelBody.appendChild(document.createElement('br'));
                    PanelBody.appendChild(body);
                    //PanelBody.appendChild(ajax);
                    PanelCollapse.appendChild(PanelBody);
                    PanelDefault.appendChild(PanelCollapse);
                    //PanelHeading.appendChild(PanelCollapse);

                    //var textnode = document.createTextNode(jsonData['data'][i]['titulo']);         // Create a text node
                    //iDiv1.appendChild(textnode);
                }
            }
           else {
                var iDiv1 = document.createElement('div');
                iDiv1.className = 'col-md-10';
                var NoDataDiv = document.createElement('div');
                NoDataDiv.setAttribute("align","center");
                NoDataDiv.appendChild(document.createTextNode("No logs found."));
                iDiv1.appendChild(NoDataDiv);
            }
           var item = document.getElementById("loading").childNodes[0];
           item.replaceWith(iDiv1);
           console.log(total_critical);
           return total_critical;
   }
   });
          };
$(document).ready(function(){
    $('#loading').html('<div align="center"><img src="/static/images/pacman_200px.gif"></div>');
    logs()
});
$('#show').click(function () {
		// add loading image to div
		$('#loading').html('<div align="center"><img src="/static/images/pacman_200px.gif"></div>');
        logs()
});
</script>
<script>
function GlobalExclusion(ruleId, title) {
    swal({
    title: 'Global Exclusion',
    text: 'Exlude this rule?',
    type: 'warning',
    showCancelButton: true,
    confirmButtonColor: '#3085d6',
    cancelButtonColor: '#d33',
    confirmButtonText: 'Yes',
    cancelButtonText: 'No',
    confirmButtonClass: 'btn btn-success',
    cancelButtonClass: 'btn btn-danger',
    buttonsStyling: true,
}). then((result) => {
       if (result.value) {
            swal('Global exclusion added!', '', 'success');
            $.ajax({
                  type: 'POST',
                  url: '/Waf2Py/Logs/ExcludeGlobal',
                  contentType: 'application/x-www-form-urlencoded',
                  data:{id_rand:'{{=id_rand}}', type:0, ruleid:ruleId, attack_name:title},
                  success: function(result){
                      swal(
                        'Success !','' + result, 'success'
                      )
                  }
                  });
        }
    })
}
//var inputValue =''
async function LocalExclusion(ruleId, title, Localpath) {
                const {value: name} = await swal({
                title: 'Exclude this rule for the following path ?',
                titleAttributes: {
                  width: 500,
                },
                text: 'Adjust the path to your needs (need to be without url encoding)',
                input: 'text',
                width: 500,
                inputAttributes: {
                  width: 100,
                },
                inputValue:Localpath,
                inputPlaceholder: 'Enter path you want to exclude ex: /page/bla.php or /page/bla.php?param=',
                showCancelButton: true,
                //var value = function(inputValue){},
              });

                if (name) {
                  $.ajax({
                  type: 'POST',
                  url: '/Waf2Py/Logs/ExcludeLocal',
                  contentType: 'application/x-www-form-urlencoded',
                  data:{id_rand:'{{=id_rand}}', type:1, ruleid:ruleId, attack_name:title, path:name},
                  success: function(result){
                      swal(
                        'Success !','' + result, 'success'
                      )
                  }
                  });
                  
        }
    }


</script>
<script>
    function Toggle(id) {
        $( "#div_header_"+id ).toggle( "slow", "linear" );
    };
    function ToggleAttack(id) {
        $( "#attack_div_"+id ).toggle( "slow", "linear" );
    };
</script>
