import React from "react";
import Table from './Table'
import {getSongs, addToCart} from './CatalogAPI'
import { capitalize } from 'lodash'
import Message from './Message'
import { SnackbarProvider } from "notistack";



function Songs(props) {
  const initial_state = {
    data: [],
    table_headers: [],
    open: false,
    message: '',
    severity: null,
    dim: false,
    nested_title: ''
  }

  const providerRef = React.useRef();

  // const { enqueueSnackbar } = useSnackbar();


  const [values, setValues] = React.useState(initial_state)

  React.useEffect(() => {
    let nested_title = ''
    let input = null
    if(props.location.pathname.split('/')[2]){
      nested_title = props.location.pathname.split('/')[2]
      input = `/${nested_title}/${props.location.pathname.split('/')[3]}`
    }
    getSongs(input, (message, severity) => {
        if(severity === 'success'){
          if(Array.isArray(message) && message.length < 1){
            setValues({...values, message: `There are no songs in DB.`, severity: 'error', open: true, nested_title: nested_title})
            return;
          }
          setValues({...values, data: message, table_headers: Object.keys(message[0]), nested_title: nested_title})
        }
        if(severity === 'error') setValues({...values, message: message, severity: severity, open: true, nested_title: nested_title})
    })
  }, []);

  const handleClose = (event, reason) => {
    // console.log(event, reason)
    setValues({ ...values, open: false });
  };

  

  // console.log(values.data)

  return (
    <SnackbarProvider ref={providerRef} maxSnack={4}>
      <Message open={values.open} message={values.message} severity={values.severity} handleClose={handleClose} />
    <Table title={`${values.nested_title} Song Catalog`} columns={values.table_headers.map(header => ({
      title: header.toUpperCase(), field: header
    }))} data={values.data} actions={[
        {
          tooltip: 'Add to cart',
          icon: 'shopping_cart',
          onClick: (evt, data) => {
            data.forEach(txn => {
              addToCart({song: txn.name}, (message, severity) => {
                setValues({...values, data: values.data, message: message, severity: severity, open: true})
                props.setCartCount(1)
              })
            })
          }
        },
      ]} />
  </SnackbarProvider>
  );
}

export default Songs;
