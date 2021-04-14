import React from 'react';
import Snackbar from '@material-ui/core/Snackbar';
import MuiAlert from '@material-ui/lab/Alert';

function Alert(props) {
    return <MuiAlert elevation={6} variant="filled" {...props} />;
}

export default function Message(props){

    // const initial_state = {
    //     open: props.open
    // };

    // const [values, setValues] = React.useState(initial_state);

    // const handleClose = (event, reason) => {
    //     // console.log(event, reason)
    //     setValues({ ...values, open: false });
    // };

    // console.log(props)

    // console.log(values)

    return (
        <Snackbar
            anchorOrigin={{vertical: 'top', horizontal: 'center' }}
            open={props.open}
            onClose={props.handleClose}
            // message={values.message}
            key={'center'}
        >
            <Alert onClose={props.handleClose} severity={props.severity}>
                {props.message}
            </Alert>
        </Snackbar>
    );
}