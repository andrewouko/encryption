import React from 'react';
import AppBar from '@material-ui/core/AppBar';
import Button from '@material-ui/core/Button';
import CameraIcon from '@material-ui/icons/PhotoCamera';
import Card from '@material-ui/core/Card';
import CardActions from '@material-ui/core/CardActions';
import CardContent from '@material-ui/core/CardContent';
import CardMedia from '@material-ui/core/CardMedia';
import CssBaseline from '@material-ui/core/CssBaseline';
import Grid from '@material-ui/core/Grid';
import Toolbar from '@material-ui/core/Toolbar';
import Typography from '@material-ui/core/Typography';
import { makeStyles } from '@material-ui/core/styles';
import Container from '@material-ui/core/Container';
// import Link from '@material-ui/core/Link';
import {getGenres} from './CatalogAPI'
import { IconButton } from '@material-ui/core';
import { Face, MusicNote } from '@material-ui/icons';
import AlbumIcon from '@material-ui/icons/Album';
import { Link } from 'react-router-dom';



const useStyles = makeStyles((theme) => ({
  icon: {
    marginRight: theme.spacing(2),
  },
  heroContent: {
    backgroundColor: theme.palette.background.paper,
    padding: theme.spacing(8, 0, 6),
  },
  heroButtons: {
    marginTop: theme.spacing(4),
  },
  cardGrid: {
    paddingTop: theme.spacing(8),
    paddingBottom: theme.spacing(8),
  },
  card: {
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
  },
  cardMedia: {
    paddingTop: '56.25%', // 16:9
  },
  cardContent: {
    flexGrow: 1,
  },
  footer: {
    backgroundColor: theme.palette.background.paper,
    padding: theme.spacing(6),
  },
}));

const cards = ['https://images.unsplash.com/photo-1572506634451-4df8fc2f1d3a?ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&ixlib=rb-1.2.1&auto=format&fit=crop&w=750&q=80', 'https://images.unsplash.com/photo-1415201364774-f6f0bb35f28f?ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&ixlib=rb-1.2.1&auto=format&fit=crop&w=1500&q=80', 'https://images.unsplash.com/photo-1535146851324-6571dc3f2672?ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&ixlib=rb-1.2.1&auto=format&fit=crop&w=750&q=80', 'https://images.unsplash.com/photo-1601643157091-ce5c665179ab?ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&ixlib=rb-1.2.1&auto=format&fit=crop&w=752&q=80', 'https://images.unsplash.com/photo-1498038432885-c6f3f1b912ee?ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&ixlib=rb-1.2.1&auto=format&fit=crop&w=750&q=80', 'https://images.unsplash.com/photo-1533106958148-daaeab8b83fe?ixlib=rb-1.2.1&ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&auto=format&fit=crop&w=751&q=80', 'https://images.unsplash.com/photo-1533106958148-daaeab8b83fe?ixlib=rb-1.2.1&ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&auto=format&fit=crop&w=751&q=80', 'https://images.unsplash.com/photo-1533106958148-daaeab8b83fe?ixlib=rb-1.2.1&ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&auto=format&fit=crop&w=751&q=80', 'https://images.unsplash.com/photo-1533106958148-daaeab8b83fe?ixlib=rb-1.2.1&ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&auto=format&fit=crop&w=751&q=80'];

export default function Genres() {
  const classes = useStyles();

  const initial_state = {
    data: [],
    open: false,
    message: '',
    severity: null,
    dim: false
  }

  const [values, setValues] = React.useState(initial_state)

  React.useEffect(() => {
    getGenres(null, (message, severity) => {
        if(severity === 'success'){
          if(Array.isArray(message) && message.length < 1){
            setValues({...values, message: `There are no genres.`, severity: 'error', open: true})
            return;
          }
          setValues({...values, data: message})
        }
        if(severity === 'error') setValues({...values, message: message, severity: severity, open: true})
    })
  }, []);


  const handleClose = (event, reason) => {
    // console.log(event, reason)
    setValues({ ...values, open: false });
  };

  

  console.log(values.data)

  return (
    <React.Fragment>
      <main>
        {/* Hero unit */}
        <div className={classes.heroContent}>
          <Container maxWidth="sm">
            <Typography component="h1" variant="h2" align="center" color="textPrimary" gutterBottom>
              Music Genres
            </Typography>
            <Typography variant="h5" align="center" color="textSecondary" paragraph>
              This is a list of music genres from our catalog. Explore the list to discover artists and albums!
            </Typography>
            <div className={classes.heroButtons}>
              <Grid container spacing={2} justify="center">
                <Grid item>
                  <Button variant="outlined" color="secondary">
                    <Link to='/albums'>
                        {`Albums`}
                    </Link>
                  </Button>
                </Grid>
                <Grid item>
                  <Button variant="outlined" color="primary">
                    <Link to='/artists'>
                        {`Artists`}
                    </Link>
                  </Button>
                </Grid>
              </Grid>
            </div>
          </Container>
        </div>
        <Container className={classes.cardGrid} maxWidth="md">
          {/* End hero unit */}
          <Grid container spacing={4}>
            {values.data.map((item, index) => (
              <Grid item key={index} xs={12} sm={6} md={4}>
                <Card className={classes.card}>
                  <CardMedia
                    className={classes.cardMedia}
                    image={cards[(Math.floor(Math.random() * cards.length))]}
                    title="Radom Splash Image from unsplash"
                  />
                  <CardContent className={classes.cardContent}>
                    <Typography gutterBottom variant="h5" component="h2">
                      {item.name}
                    </Typography>
                    <Typography>
                      {` — ${item.date_added.split('T')[0]}`}
                    </Typography>
                  </CardContent>
                  <CardActions>
                  <Button
                    variant="outlined"
                    color="primary"
                    size="small"
                    startIcon={<Face />}
                >
                    <Link to={'/artists/'+item.name+'/genre'}>
                        {`Artists`}
                    </Link>
                </Button>
                <Button
                    variant="outlined"
                    color="secondary"
                    size="small"
                    startIcon={<AlbumIcon />}
                >
                    <Link to={'/albums/'+item.name+'/genre'}>
                        {`Albums`}
                    </Link>
                </Button>
                  </CardActions>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Container>
      </main>
    </React.Fragment>
  );
}